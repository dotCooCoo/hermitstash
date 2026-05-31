"use strict";
var observability = require("./observability");

/**
 * Framework error base class + cross-module operational error classes.
 *
 * Two scopes live here:
 *
 *   1. FrameworkError — base class every framework error class extends.
 *      Provides a single `instanceof FrameworkError` check (replacing the
 *      scattered `isXxxError` boolean flags) plus a stable shape: { name,
 *      code, message, isFrameworkError: true }.
 *
 *   2. Cross-module operational error classes — errors raised by more
 *      than one module that share a logical domain (e.g. ObjectStoreError
 *      raised by the 5 object-store adapters + the umbrella). These can't
 *      live in the umbrella module because adapters would need a circular
 *      require to access them. They live here, where every adapter can
 *      import from the same place.
 *
 *   3. defineClass(name, opts) — factory that produces a FrameworkError
 *      subclass with the standard shape. Eliminates the boilerplate that
 *      every per-domain error class was duplicating across lib/.
 *
 * Per-domain VALIDATION errors (SafeSqlError, SafeJsonError, SafeBufferError,
 * SafeAsyncError, AtomicFileError, ChainWriterError, ClusterStorageError,
 * NotLeaderError, FrameworkSchemaError, *SafeError parser families) stay
 * co-located with their primitive module — they're single-owner, single-
 * domain, and the *-safe filename convention already declares ownership.
 * They extend FrameworkError so the unified `instanceof` check works.
 *
 * Operational error classes here all share:
 *   { name, code, message, permanent: bool, isFrameworkError: true }
 * Adapters that talk over HTTP also carry `statusCode` for retry
 * classification.
 */

class FrameworkError extends Error {
  constructor(message, code) {
    super(message);
    this.name = "FrameworkError";
    this.code = code || "framework/invalid";
    this.isFrameworkError = true;
  }
}

// defineClass — factory for the standard FrameworkError-subclass shape
// every per-domain error followed by hand. Variants the factory covers:
//
//   defineClass("MyError")
//     constructor: (code, message, permanent)
//     fields:      name, permanent, isMyError
//
//   defineClass("MyError", { withStatusCode: true })
//     constructor: (code, message, permanent, statusCode)
//     fields:      + statusCode  (HTTP-shaped operational errors)
//
//   defineClass("MyError", { alwaysPermanent: true })
//     constructor: (code, message)
//     fields:      permanent always true (auth failures, validation)
//
//   defineClass("MyError", { withCause: true })
//     constructor: (code, message, cause)
//     fields:      + cause  (errors that wrap an upstream cause)
//
// Returns the constructor. Operators can attach extra static helpers
// to it after creation if they need to.
function defineClass(name, opts) {
  if (typeof name !== "string" || name.length === 0) {
    throw new Error("defineClass: name must be a non-empty string");
  }
  opts = opts || {};
  var alwaysPermanent = !!opts.alwaysPermanent;
  var withStatusCode  = !!opts.withStatusCode;
  var withCause       = !!opts.withCause;
  if (alwaysPermanent && (withStatusCode || withCause)) {
    throw new Error("defineClass: alwaysPermanent is mutually exclusive with withStatusCode / withCause");
  }
  var flagKey = "is" + name;

  // Generated class — uses an anonymous class expression so we can set
  // the constructor name explicitly via Object.defineProperty (matters
  // for stack traces and instanceof debugging).
  var GeneratedError = class extends FrameworkError {
    constructor(code, message, arg3, arg4) {
      super(message, code);
      this.name = name;
      this[flagKey] = true;
      if (alwaysPermanent) {
        this.permanent = true;
      } else if (withCause) {
        this.cause = arg3;
      } else {
        this.permanent = !!arg3;
        if (withStatusCode) this.statusCode = arg4;
      }
      // Framework-error class counter — routed into framework_errors_total
      // when a metrics registry is active. observability.event is safe to
      // call here even during framework-error's own load: observability's
      // dependencies on metrics + tracing are themselves lazy-required
      // and only resolve at first call (post-load).
      observability.safeEvent("error.construct", 1, { class: name });
    }
  };
  Object.defineProperty(GeneratedError, "name", { value: name, configurable: true });
  // Per-class factory — collapses the boilerplate every module used to
  // write as `function _err(code, msg, perm) { return new XxxError(...); }`.
  // Now: `var _err = XxxError.factory;` (one line, same call shape).
  GeneratedError.factory = function (code, message, arg3, arg4) {
    return new GeneratedError(code, message, arg3, arg4);
  };
  return GeneratedError;
}

// ---- Cross-module operational classes (defined via the factory) ----

var ObjectStoreError      = defineClass("ObjectStoreError",      { withStatusCode: true });
var LogStreamError        = defineClass("LogStreamError",        { withStatusCode: true });
var QueueError            = defineClass("QueueError");
// RedisError covers transport (CONNECT/CONNECT_TIMEOUT/SOCKET/WRITE),
// protocol parsing (PROTOCOL/BAD_URL/BAD_OPTS), command-level
// (REDIS_REPLY/COMMAND_TIMEOUT), and lifecycle (CLOSED/RECONNECT_GAVE_UP).
// Transient by default — operators wrap calls in retry/breaker. Bad-opts
// and bad-URL paths surface as alwaysPermanent code names so retry sees
// them and skips immediately rather than hammering a misconfig.
var RedisError            = defineClass("RedisError");
var ExternalDbError       = defineClass("ExternalDbError");
var ClusterError          = defineClass("ClusterError");
var ClusterProviderError  = defineClass("ClusterProviderError");
var HandlerError          = defineClass("HandlerError",          { withCause: true });
var StorageError          = defineClass("StorageError");
// AuthError covers password / passkey / TOTP failures at the framework
// layer (lib/auth/*). Always permanent — auth failures are not transient
// ("retry might work"); they're "this credential doesn't match" or
// "this input was malformed".
var AuthError             = defineClass("AuthError",             { alwaysPermanent: true });
var JobsError             = defineClass("JobsError");
var SchedulerError        = defineClass("SchedulerError");
var SessionError          = defineClass("SessionError");
var SlugError             = defineClass("SlugError",             { alwaysPermanent: true });
var WebhookError          = defineClass("WebhookError",          { alwaysPermanent: true });
var ApiKeyError           = defineClass("ApiKeyError",           { alwaysPermanent: true });
var PermissionsError      = defineClass("PermissionsError",      { alwaysPermanent: true });
// CacheError is alwaysPermanent: bad opts / missing key / closed-state
// errors are programming bugs, not transient. Backend-level transient
// failures (cluster DB unavailable mid-fetch) become observability +
// audit signals; they don't escape as exceptions to the caller.
var CacheError            = defineClass("CacheError",            { alwaysPermanent: true });
// SeederError is alwaysPermanent: load failures, bad-shape seed files,
// missing deps, and cycle errors are programming bugs. Per-seed runtime
// failures get wrapped in this class with the seed name in the message
// — operators see "seeders/run-failed: 0042-x.js: <cause>" not a raw
// driver exception.
var SeederError           = defineClass("SeederError",           { alwaysPermanent: true });
// I18nError is alwaysPermanent: bad locale tags, malformed translation
// trees, missing-key in throw mode, and bad input to formatters are
// programming bugs. Missing keys in default ("return-key") mode return
// the key without throwing — runtime hot-path semantics, not error.
var I18nError             = defineClass("I18nError",             { alwaysPermanent: true });
// NotifyError is alwaysPermanent: bad opts, unknown channels, transport
// contract violations are programming bugs. Per-send transient failures
// (the kind retry can recover) are surfaced from the underlying transport
// with their own shape; only after retry exhaustion does notify wrap
// them into NotifyError SEND_FAILED — at that point they ARE permanent.
var NotifyError           = defineClass("NotifyError",           { alwaysPermanent: true });
// TestingError is alwaysPermanent: bad inputs to test helpers
// (NaN clock, non-fn predicate, path-traversal tempDir prefix) and
// waitFor timeouts are programming bugs at test-write time.
var TestingError          = defineClass("TestingError",          { alwaysPermanent: true });
// LockoutError is alwaysPermanent: misconfig at create() and bad keys at
// recordFailure/recordSuccess/check/unlock are programming bugs. The
// "account is currently locked" condition is NOT an error — recordFailure
// returns { locked: true, lockedUntil } so the caller decides the response.
var LockoutError          = defineClass("LockoutError",          { alwaysPermanent: true });
// FileUploadError is alwaysPermanent: chunk-hash mismatch / oversized
// chunk / oversized total file / manifest verification failure are all
// caller-shape errors that won't succeed on retry. Operators wrap the
// route handler with their own retry policy if they want client-side
// resumability.
var FileUploadError       = defineClass("FileUploadError",       { alwaysPermanent: true });
// StaticServeError covers the download-side surface of staticServe.create.
// withStatusCode: true so the framework can translate to operator-meaningful
// HTTP responses (403 permission_denied, 404 not_found, 412 precondition_failed,
// 416 range_not_satisfiable, 429 quota_exceeded, 451 retention_blocked).
var StaticServeError      = defineClass("StaticServeError",      { withStatusCode: true });
// GateContractError covers gate-contract violations (operator-supplied
// gate is malformed / hook threw / runtime exceeded). alwaysPermanent
// because these are programming-bug-shaped, not transient.
var GateContractError     = defineClass("GateContractError",     { alwaysPermanent: true });
// GuardCsvError covers csv-shape violations on the serialize / sanitize /
// validate paths. alwaysPermanent — chunk-shape errors / formula-injection
// attempts / schema drift are all caller-shape errors.
var GuardCsvError         = defineClass("GuardCsvError",         { alwaysPermanent: true });
// GuardAllError covers parity-check failures, exceptFor opt validation, and
// override opt validation in the b.guardAll registry. alwaysPermanent — every
// case is a config-time programming bug, not a transient runtime condition.
var GuardAllError         = defineClass("GuardAllError",         { alwaysPermanent: true });
// GuardHtmlError covers html-shape violations on validate / sanitize / escape
// paths. alwaysPermanent — XSS attempts / dangerous-tag detections / DOM
// clobbering are all caller-shape errors.
var GuardHtmlError        = defineClass("GuardHtmlError",        { alwaysPermanent: true });
// GuardSvgError covers svg-shape violations: dangerous tags (script /
// foreignObject / use cross-origin / handler), DOCTYPE entity expansion
// (billion laughs / XXE), animation-element attributeName targeting href,
// SVGZ compressed payloads, SSRF-shape href references. alwaysPermanent.
var GuardSvgError         = defineClass("GuardSvgError",         { alwaysPermanent: true });
// GuardFilenameError covers filename-shape violations: path traversal,
// null-byte truncation, Windows reserved names (CON / PRN / AUX / ...),
// NTFS alternate data streams, leading/trailing whitespace + trailing dots
// (Windows strips them silently), unicode bidi/RTLO file-name spoofing,
// overlong UTF-8 encoding, length caps. alwaysPermanent.
var GuardFilenameError    = defineClass("GuardFilenameError",    { alwaysPermanent: true });
// GuardArchiveError covers archive-shape violations: zip-slip path
// traversal, symlink + hardlink escape, decompression-ratio bombs,
// nested-archive depth, file-count + total-size + per-entry-size caps,
// magic-byte / format-claim mismatch, duplicate entries, encryption-
// claim mismatch. alwaysPermanent.
var GuardArchiveError     = defineClass("GuardArchiveError",     { alwaysPermanent: true });
// GuardJsonError covers json-shape violations: prototype pollution
// (__proto__/constructor/prototype), depth + breadth + key-count bombs,
// duplicate keys, NaN/Infinity/comments (JSON5 extensions), bidi/null
// in string values, numeric precision loss, total-size cap.
// alwaysPermanent.
var GuardJsonError        = defineClass("GuardJsonError",        { alwaysPermanent: true });
// GuardYamlError covers yaml-shape violations: deserialization-tag
// injection (!!python/object / !!java.util.HashMap / custom !Class),
// anchor recursion (billion laughs), Norway-problem implicit booleans,
// leading-zero octals, duplicate keys, multi-document streams, depth +
// node-count + size caps. alwaysPermanent.
var GuardYamlError        = defineClass("GuardYamlError",        { alwaysPermanent: true });
// GuardXmlError covers xml-shape violations: XXE, billion-laughs entity
// expansion, parameter entities, external DTD subset, XInclude, schema-
// fetch (xsi:schemaLocation), processing instructions, CDATA, depth +
// element-count + attribute-count caps. alwaysPermanent.
var GuardXmlError         = defineClass("GuardXmlError",         { alwaysPermanent: true });
// GuardMarkdownError covers markdown-shape violations: raw-HTML smuggling
// (including the CVE-2026-30838 whitespace-in-tag-name bypass), dangerous
// link / image / autolink / reference-link URL schemes (javascript: / data:
// text/html / vbscript: / file: / jar:), entity-encoded scheme bypass,
// front-matter payloads, ReDoS-prone emphasis / nesting / autolink mass,
// HTML-comment smuggling, code-fence language injection, depth + link
// count + image count + line count + size caps. alwaysPermanent.
var GuardMarkdownError    = defineClass("GuardMarkdownError",    { alwaysPermanent: true });
// GuardEmailError covers email-shape violations: SMTP smuggling (bare
// CR/LF in body, embedded SMTP verbs), CRLF header injection, RFC 5321
// /5322 local-part / domain / total-length caps, multi-@ violations,
// IDN homograph spoofing (mixed-script confusable codepoints), display-
// name vs envelope mismatch, bare IP literal addresses, comment syntax
// in addresses, bidi/null/control chars in headers + addresses, header-
// folding smuggling, BOM injection. alwaysPermanent.
var GuardEmailError       = defineClass("GuardEmailError",       { alwaysPermanent: true });
// GuardDomainError covers domain-name identifier violations: RFC 1035
// length-cap overflow, RFC 952/1123 LDH-rule violations, IDN homograph /
// mixed-script confusables, BIDI / zero-width / control-byte injection,
// Punycode malformation, RFC 6761 special-use domains, IPv4-as-domain
// confusion (CVE-2021-22931), IPv6 bracket literals, single-label / TLD-
// only strings, wildcard labels, RFC 8552 underscore-label misuse, DGA
// high-entropy labels. alwaysPermanent.
var GuardDomainError      = defineClass("GuardDomainError",      { alwaysPermanent: true });
// GuardUuidError covers UUID identifier violations: shape malformation
// (non-canonical / non-hex), RFC 9562 §4.2 unassigned version digits,
// non-RFC 4122 variant bits, nil UUID (§5.9) / max UUID (§5.10) sentinel
// leakage, urn:uuid: + Microsoft GUID braces forms outside the operator's
// declared formatPolicy, BIDI / zero-width / control-byte / null-byte
// universal refuse. alwaysPermanent.
var GuardUuidError        = defineClass("GuardUuidError",        { alwaysPermanent: true });
// GuardCidrError covers CIDR identifier violations: shape malformation,
// IPv4 octet overflow, IPv6 zero-group ambiguity, mask out-of-range,
// network-address misalignment (host bits set), reserved-range membership
// (RFC 1918, loopback, link-local, multicast, documentation, benchmarking,
// CGNAT, IPv6 ULA / link-local / multicast / documentation), IPv4-mapped
// IPv6 dual-stack confusion, BIDI / zero-width / control / null-byte
// universal refuse. alwaysPermanent.
var GuardCidrError        = defineClass("GuardCidrError",        { alwaysPermanent: true });
// GuardTimeError covers RFC 3339 / ISO 8601 datetime identifier
// violations: shape malformation, year-window overflow (pre-epoch /
// far-future), naive datetime (no offset), non-UTC offset, leap-second
// `60` field policy, excessive fractional precision, date-only /
// time-only refuse, BIDI / zero-width / control / null-byte universal
// refuse, structural range violations (month / day-in-month / hour /
// minute / second). alwaysPermanent.
var GuardTimeError        = defineClass("GuardTimeError",        { alwaysPermanent: true });
// GuardMimeError covers RFC 6838 media-type identifier violations:
// shape malformation (missing `/`, bad type/subtype tokens), parameter
// injection (multiple params, bad name/value tokens, malformed quoted-
// string), wildcard `*/*` outside Accept context, vendor / personal /
// unregistered tree namespaces, risky-type refuse list (executable +
// script-host content types), BIDI / zero-width / control / null-byte
// universal refuse. alwaysPermanent.
var GuardMimeError        = defineClass("GuardMimeError",        { alwaysPermanent: true });
// GuardJwtError covers JWT identifier violations: shape malformation
// (not 3 base64url segments), alg=none refuse (canonical CVE-class —
// CVE-2015-9235 jsonwebtoken alg:none / CVE-2018-0114 Cisco node-jose
// embedded-JWK key confusion), alg-allowlist
// drift, kid path-traversal (operator keyResolver path-injection
// class), typ confusion, oversized header / payload / signature,
// exp / nbf / iat sanity, missing required claims, unknown crit
// fields (RFC 7515 §4.1.11), BIDI / null / control / zero-width
// universal refuse. alwaysPermanent.
var GuardJwtError         = defineClass("GuardJwtError",         { alwaysPermanent: true });
// GuardOauthError covers OAuth flow-shape violations: PKCE missing /
// non-S256 (downgrade-attack class), state missing (RFC 6749 §10.12
// CSRF class), redirect_uri not in operator allowlist (exact-match
// per OAuth 2.1), response_type allowlist drift, scope-token shape
// (RFC 6749 §3.3), issuer missing on callback (RFC 9207 IdP-mix-up),
// authorization-code reuse (RFC 6749 §10.5), oversized parameter,
// BIDI / null / control / zero-width universal refuse.
// alwaysPermanent.
var GuardOauthError       = defineClass("GuardOauthError",       { alwaysPermanent: true });
// GuardGraphqlError covers GraphQL request-shape violations: query
// depth bombs (N² query-shape DoS), alias-bomb breadth DoS,
// introspection in production, batch-query DoS, persisted-query
// enforcement, operation-name allowlist drift, variable type
// confusion, oversized query / variable / total bytes, BIDI / null /
// control / zero-width universal refuse on the query string.
// alwaysPermanent.
var GuardGraphqlError     = defineClass("GuardGraphqlError",     { alwaysPermanent: true });
// GuardShellError covers shell-arg identifier violations: POSIX +
// cmd.exe metacharacters, $(...) / ${...} command + parameter
// substitution, backtick substitution, process substitution
// (`<(...)` / `>(...)`), `$VAR` parameter expansion, newline
// injection, leading-hyphen option-flag injection (`-rf` / `--exec`
// class), BIDI / null / control / zero-width universal refuse.
// alwaysPermanent.
var GuardShellError       = defineClass("GuardShellError",       { alwaysPermanent: true });
// GuardRegexError covers regex-pattern identifier violations: nested
// quantifier ReDoS class (CVE-2024-21538 / CVE-2022-25929), alternation
// with quantifier, bounded-repeat upper-bound overflow, lookaround
// with internal quantifier, oversized pattern, BIDI / null / control /
// zero-width universal refuse. alwaysPermanent.
var GuardRegexError       = defineClass("GuardRegexError",       { alwaysPermanent: true });
// GuardJsonpathError covers JSONPath identifier violations: filter
// expression (`?(...)` — RCE class in eval-based implementations),
// script expression, JS-source hints (`eval` / `new` / `function` /
// `=>` / `;`), excessive bracket nesting, recursive-descent depth
// bombs, oversized pattern, BIDI / null / control / zero-width
// universal refuse. alwaysPermanent.
var GuardJsonpathError    = defineClass("GuardJsonpathError",    { alwaysPermanent: true });
// GuardTemplateError covers Server-Side Template Injection (SSTI)
// identifier violations: Jinja / Django / Twig / Liquid / Handlebars /
// AngularJS `{{...}}` + `{%...%}` shapes (CVE-2024-22195 / 26139 /
// 23348 class), ERB / Tornado `<%...%>`, Pug `#{...}` / `!{...}`
// interpolation, Mako / Velocity / Tornado `${...}`, Velocity
// directives (#set / #if / #foreach), BIDI / null / control / zero-
// width universal refuse. alwaysPermanent.
var GuardTemplateError    = defineClass("GuardTemplateError",    { alwaysPermanent: true });
// GuardImageError covers image-metadata violations: magic-byte vs
// declared-MIME mismatch (drive-by content-type confusion class),
// polyglot (multiple format magic bytes — PHP-in-JPEG / JS-in-PNG
// class), unknown magic-byte, SVG-routing-via-image bypass, oversized
// dimensions / frame count, oversized total bytes. alwaysPermanent.
var GuardImageError       = defineClass("GuardImageError",       { alwaysPermanent: true });
// GuardPdfError covers PDF-metadata violations: magic-byte missing,
// JavaScript action (`/JS` / `/JavaScript` — RCE class), Launch
// action, OpenAction trigger, embedded-file presence + count cap,
// encrypted PDF refuse, polyglot signal, oversized bytes / page
// count. alwaysPermanent.
var GuardPdfError         = defineClass("GuardPdfError",         { alwaysPermanent: true });
// GuardAuthError covers composite auth-bundle violations: aggregates
// guardJwt + guardOauth + b.cookies.parseSafe + light header-smuggling
// detection into a single gate with `source` tagging on each issue.
// alwaysPermanent.
var GuardAuthError        = defineClass("GuardAuthError",        { alwaysPermanent: true });
// DoraError covers DORA Article 17 incident-reporting workflow errors
// (classification refusal, report-shape validation, ESA-template
// generation, audit-chain integration). Permanent — these are
// configuration / submission errors, not transient.
var DoraError             = defineClass("DoraError",             { alwaysPermanent: true });
// ComplianceError covers compliance-coordinator misuse: unknown
// posture name, runtime-switch refusal, assertion failures.
// Permanent — these are configuration errors, not transient.
var ComplianceError       = defineClass("ComplianceError",       { alwaysPermanent: true });
// SmtpPolicyError covers MTA-STS / DANE / TLS-RPT misuse: bad-policy
// shape, fetch failures, TLSA-record format errors, missing records.
// Permanent — these are policy / DNS configuration errors, not
// transient.
var SmtpPolicyError       = defineClass("SmtpPolicyError",       { alwaysPermanent: true });
// MailAuthError covers SPF / DKIM-verify / DMARC / ARC misuse: bad
// record shape, fetch failures, missing keys, alignment issues.
// Permanent — DNS-config / message-shape errors, not transient.
var MailAuthError         = defineClass("MailAuthError",         { alwaysPermanent: true });
// MailArfError covers RFC 5965 Abuse Reporting Format ingest failures:
// missing required Feedback-Type / User-Agent fields, malformed
// multipart/report, message/feedback-report MIME-type mismatch, parse
// errors. Permanent — the report shape is operator-supplied input.
var MailArfError          = defineClass("MailArfError",          { alwaysPermanent: true });
// MailBimiError covers RFC 9091 BIMI VMC / CMC chain validation
// + Tiny-PS SVG profile violations: VMC fetch failures, X.509 chain
// validation failures, subjectAltName URI / BIMI domain mismatch,
// missing BIMI policy OID (1.3.6.1.5.5.7.3.31 mark verification),
// Tiny-PS SVG profile violations (root, version, baseProfile, scripts,
// external refs, viewBox, byte cap). Permanent — every case is a
// brand / certificate / asset shape error.
var MailBimiError         = defineClass("MailBimiError",         { alwaysPermanent: true });
// SseError covers Server-Sent Events stream-shape violations: newline
// or CR or NUL injection in event:/id:/data: fields (CVE-2026-33128
// h3, CVE-2026-29085 Hono, CVE-2026-44217 sse-channel — newline in
// any of the three fields enables event-spoofing, data-injection, or
// Last-Event-ID reconnect corruption), control-char injection in
// retry: numeric, oversized field caps, attempts to write after
// stream close. Permanent — these are caller-shape errors.
var SseError              = defineClass("SseError",              { alwaysPermanent: true });
// McpError covers Model Context Protocol server-side violations:
// unauthenticated tool/resource invocations (CVE-2026-33032 nginx-ui
// auth-bypass class), confused-deputy via static client IDs +
// dynamic client registration (CVE-2025-6514 mcp-remote OAuth RCE
// class), consent-cookie leakage, malformed Authorization header,
// tool/resource name path traversal. Permanent — protocol-shape
// errors.
var McpError              = defineClass("McpError",              { alwaysPermanent: true });
// AiInputError covers prompt-injection classifier violations: malformed
// input shape, classifier-result-shape errors, oversized input bypass.
// Permanent — caller-shape errors.
var AiInputError          = defineClass("AiInputError",          { alwaysPermanent: true });
// AiOutputError covers LLM output-handling violations raised by
// b.ai.output.sanitize / b.ai.output.redact: malformed input shape
// (non-string), oversized output bypass (exceeds maxBytes cap), bad
// maxBytes opt, unknown redaction entity. Permanent — caller-shape
// errors that retry will not recover. OWASP LLM05:2025 (Improper
// Output Handling) + LLM02:2025 (Sensitive Information Disclosure).
var AiOutputError         = defineClass("AiOutputError",         { alwaysPermanent: true });
// AiPromptError covers LLM prompt-assembly violations raised by
// b.ai.prompt.template: malformed segment shape (non-string system /
// context / user), bad maxBytes / nonceBytes opt, oversized assembled
// prompt. Permanent — caller-shape errors that retry will not recover.
// OWASP LLM01:2025 (Prompt Injection — indirect / data-plane injection
// from untrusted context).
var AiPromptError         = defineClass("AiPromptError",         { alwaysPermanent: true });
// A2aError covers A2A (Agent-to-Agent) protocol violations: signed-
// agent-card signature mismatch, expired card, unknown card id,
// malformed card shape, signature-algorithm allowlist drift.
// Permanent.
var A2aError              = defineClass("A2aError",              { alwaysPermanent: true });
// GraphqlFederationError covers _service.sdl trust-boundary violations:
// missing or malformed router-token, replay (nonce already seen),
// unauthorized SDL probe. Permanent.
var GraphqlFederationError = defineClass("GraphqlFederationError", { alwaysPermanent: true });
// Fda21Cfr11Error covers FDA 21 CFR Part 11 §11.10(e) audit-content
// shape + §11.50/§11.70 electronic-signature shape violations: missing
// printedName / dateTimeUtc / signatureMeaning / predicateRule / signed
// record bind, before/after pair missing on a GxP audit row, signature-
// algorithm allowlist drift, posture interceptor refusal. Permanent —
// every case is operator-supplied data shape, not transient.
var Fda21Cfr11Error       = defineClass("Fda21Cfr11Error",       { alwaysPermanent: true });
// AuditDailyReviewError covers PCI DSS 4.0 Req 10.4.1.1 daily-review
// misconfiguration: bad cron / lookback / severity threshold, missing
// notify callback under threshold-bearing posture, audit-source not
// queryable. Permanent — config-time errors.
var AuditDailyReviewError = defineClass("AuditDailyReviewError", { alwaysPermanent: true });
// AuditSegregationError covers SOX §404 / SOC 2 CC1.3 actor-binding
// violations: bound-actor mismatch on emit, missing db-role context,
// trigger-installation failure when sox-404 / soc2 posture demands it.
// Permanent — operator-misconfig or in-flight identity mismatch.
var AuditSegregationError = defineClass("AuditSegregationError", { alwaysPermanent: true });
// DdlChangeControlError covers SOX §404 / PCI-DSS DDL change-control
// violations: insufficient approvers, approval window violation,
// signature-mismatch on apply, duplicate approval, application of an
// already-applied or rejected change. Permanent.
var DdlChangeControlError = defineClass("DdlChangeControlError", { alwaysPermanent: true });
// LegalHoldError covers subject-level legal-hold registry violations:
// missing subjectId, malformed reason/citation, duplicate placement,
// release-without-placement, bad opts. Permanent — config / API
// shape errors, not transient.
var LegalHoldError        = defineClass("LegalHoldError",        { alwaysPermanent: true });
// WormViolationError covers operator-declared WORM (write-once-read-
// many) trigger-installation failures and posture-asserted boot
// gates: declareWorm called on a non-existent table, table requires
// WORM under sec-17a-4 / finra-4511 / fda-21cfr11 but none declared,
// operator attempted to drop the WORM trigger outside a sanctioned
// retention.purge flow. Permanent.
var WormViolationError    = defineClass("WormViolationError",    { alwaysPermanent: true });
// SandboxError covers operator-supplied transform-source isolation
// failures: bad opts at create() (non-string source, non-finite
// timeoutMs / maxBytes, allowed-list contains a non-allowlisted
// global), worker-thread spawn failure, timeout exceeded, peak-bytes
// overrun, non-allowlisted-global access, output-shape-too-large,
// runtime exceptions inside the transform. Permanent — every case is
// either operator-misconfig or a transform that the host should
// refuse rather than retry. Operator decides at the call site whether
// to surface the refusal as a 4xx or to fall back to a default value.
var SandboxError          = defineClass("SandboxError",          { alwaysPermanent: true });
// DlpError — outbound DLP scanner refusal raised by
// b.redact.installOutboundDlp's interceptors when the classifier verdict
// is "refuse". Permanent; the request body must be operator-corrected
// before re-attempt rather than retried as-is.
var DlpError              = defineClass("DlpError",              { alwaysPermanent: true });
// AuthBotChallengeError — challenge / escalation refusal raised by
// b.authBotChallenge when the operator-supplied challengeFn is
// missing, returns a non-boolean verdict, or throws. Permanent.
var AuthBotChallengeError = defineClass("AuthBotChallengeError", { alwaysPermanent: true });
// BotChallengeError — verifier-side errors raised by b.auth.botChallenge
// (Cloudflare Turnstile / hCaptcha / reCAPTCHA-v3 token siteverify):
// invalid token shape, timeout, hostname / action allowlist mismatch,
// provider reported success=false, malformed response body. Permanent.
var BotChallengeError     = defineClass("BotChallengeError",     { alwaysPermanent: true });
// SessionDeviceBindingError — fingerprint-drift refusal raised by
// b.sessionDeviceBinding when create-time opts are malformed or the
// boundKeyResolver returns a non-Buffer. Permanent.
var SessionDeviceBindingError = defineClass("SessionDeviceBindingError", { alwaysPermanent: true });
// AcmeError — RFC 8555 ACME + RFC 9773 ACME Renewal Information
// (ARI) protocol violations raised by b.acme: bad opts at create
// (non-https directory URL, missing accountKey, malformed audit hook),
// directory-fetch failure shape, newOrder/finalize/retrieveCert
// HTTP-status / response-shape errors, ARI window parse failures,
// retrieveCert returning non-PEM bytes, renewIfDue called before
// retrieveCert / before ARI URL is reachable. Permanent — every case
// is operator-misconfig or a CA-side response shape the framework
// refuses to coerce. withStatusCode so HTTP-shaped failures from the
// CA surface as a typed status for retry classification.
var AcmeError             = defineClass("AcmeError",             { withStatusCode: true });

// HpkeError — RFC 9180 Hybrid Public-Key Encryption (lib/crypto-hpke.js).
// Bad opts at the call site, KEM encap/decap failures, AEAD tag failures.
var HpkeError             = defineClass("HpkeError",             { alwaysPermanent: true });
// TlsExporterError — RFC 9266 TLS-Exporter channel binding
// (lib/tls-exporter.js). Non-TLS sockets, TLS<1.3 sessions, short
// exporter outputs.
var TlsExporterError      = defineClass("TlsExporterError",      { alwaysPermanent: true });
// HttpSigError — RFC 9421 HTTP Message Signatures (lib/http-message-
// signature.js). Bad opts, missing covered components, unsupported alg.
var HttpSigError          = defineClass("HttpSigError",          { alwaysPermanent: true });
// HttpClientError — outbound httpClient streaming primitives
// (b.httpClient.downloadStream / b.httpClient.uploadMultipartStream).
// withStatusCode so HTTP-shaped failures (404, 500, 503) carry the
// upstream status for retry classification. Codes follow the
// "httpclient/<reason>" shape: hash-mismatch, dest-not-writable,
// missing-file, http-error, etc.
var HttpClientError       = defineClass("HttpClientError",       { withStatusCode: true });
// KeychainError — b.keychain (lib/keychain.js). Bad opts at config time,
// native-tool exec failure (security / secret-tool / PowerShell
// CredentialManager), file-fallback unseal / shape failure, oversized
// native-tool output. alwaysPermanent — every case is operator-misconfig
// or a host-environment condition the framework refuses to coerce.
var KeychainError         = defineClass("KeychainError",         { alwaysPermanent: true });
// WatcherError — b.watcher recursive-fs.watch wrapper (lib/watcher.js).
// Bad opts at create (non-string root, missing root, bad ignore pattern,
// non-finite debounceMs, non-function hook), recursive-watch unsupported
// on the host platform/kernel, fs.watch start failure, pending-event
// queue overflow under runaway-directory pressure. alwaysPermanent —
// every case is config-misuse or a host-environment refusal the
// framework will not coerce.
var WatcherError          = defineClass("WatcherError",          { alwaysPermanent: true });
// LocalDbThinError — b.localDb.thin lightweight node:sqlite wrapper
// (lib/local-db-thin.js). Bad opts at create, node:sqlite unavailable
// on the host Node build, integrity_check failure under recovery:
// "refuse", recovery-rename I/O failure, post-close handle reuse, bad
// SQL passed to prepare/run/query. alwaysPermanent — every case is
// caller-shape misuse or an irrecoverable on-disk condition.
var LocalDbThinError      = defineClass("LocalDbThinError",      { alwaysPermanent: true });
// RouterError covers operator-shape violations on the router primitive:
// invalid `allowedRedirectOrigins` opt at create time, and cross-origin
// `res.redirect()` targets that are not on the allowlist. alwaysPermanent
// — every case is config-time programming bug or an outbound-redirect
// shape error that retry will not recover.
var RouterError           = defineClass("RouterError",           { alwaysPermanent: true });
// WorkerPoolError — b.workerPool (lib/worker-pool.js). Bad opts at
// config (size / maxQueueDepth / taskTimeoutMs out of range, non-
// absolute scriptPath, non-function onExit), runtime queue-full,
// per-task timeout, worker spawn / error / non-zero exit, malformed
// reply envelope, terminate-aborted tasks. alwaysPermanent — every
// case is operator-misconfig or worker-script bug; retry without a
// fix would just repeat the failure.
var WorkerPoolError       = defineClass("WorkerPoolError",       { alwaysPermanent: true });
// ArgParserError — b.argParser declarative CLI argument parser
// (lib/arg-parser.js). Bad opts at create time (unsupported flag type,
// duplicate flag/alias, malformed flag/command name, prototype-polluting
// name like __proto__/constructor/prototype), bad parse-time argv (not
// an array, non-string elements, unknown flag/command, missing required
// flag, unparseable number/boolean coercion, missing flag value).
// alwaysPermanent — every case is operator-shape misuse the framework
// will not coerce; the operator fixes the spec or the argv source.
var ArgParserError        = defineClass("ArgParserError",        { alwaysPermanent: true });
// DaemonError — b.daemon (lib/daemon.js). Bad opts at start/stop, pidfile
// already held by a live PID, spawn failure for detached-fork mode,
// log-file open failure, kill() failure outside ESRCH. alwaysPermanent —
// every case is operator-misconfig or a host-environment condition the
// framework refuses to coerce; transient-shaped failures (process
// already exited between read and kill) are surfaced as a non-error
// "stopped: false, reason: stale" return.
var DaemonError           = defineClass("DaemonError",           { alwaysPermanent: true });
// SelfUpdateError — b.selfUpdate (lib/self-update.js). Bad opts at
// poll/verify/swap/rollback, non-2xx releases-feed response, malformed
// JSON, missing tag_name, signature verify mismatch, atomic-swap or
// rollback failure, cross-device install failure. alwaysPermanent —
// every case is operator-misconfig or a release-feed shape the
// framework refuses to coerce. Operators wrap the call in their own
// retry policy when polling against a flaky CDN.
var SelfUpdateError       = defineClass("SelfUpdateError",       { alwaysPermanent: true });
// MailUnsubscribeError — b.mail.unsubscribe (lib/mail-unsubscribe.js).
// RFC 8058 / RFC 2369 / RFC 2919 List-* header builder violations:
// non-https URL in url/help/archive, non-mailto in mailto/owner,
// invalid list-id shape per RFC 2919 §3, control bytes / over-length
// header values. alwaysPermanent — every case is operator-misconfig
// at config-time the framework refuses to coerce.
var MailUnsubscribeError  = defineClass("MailUnsubscribeError",  { alwaysPermanent: true });
// FidoMds3Error — b.auth.fidoMds3 (lib/auth/fido-mds3.js). FIDO MDS3
// metadata BLOB verification + AAGUID lookup violations: BLOB fetch
// failure (non-2xx, oversize, network), JWS shape mismatch, certificate
// chain validation failure against the FIDO Alliance MDS3 root,
// signature verification failure, payload schema violation
// (missing entries / nextUpdate / no), nextUpdate parse failure,
// AAGUID lookup against an authenticator carrying a REVOKED /
// USER_KEY_PHYSICAL_COMPROMISE / USER_KEY_REMOTE_COMPROMISE status
// report. alwaysPermanent — every case is configuration / network /
// signing-shape errors that retry alone won't recover.
var FidoMds3Error         = defineClass("FidoMds3Error",         { alwaysPermanent: true });
// PublicSuffixError — b.publicSuffix (lib/public-suffix.js). Bad
// domain input at lookup time (non-string, empty, overlong, control-
// byte-bearing, IDN-normalization failure) and missing-vendored-data
// at module-init are both alwaysPermanent — every case is operator-
// shaped (caller passed garbage) or packaging-shaped (vendored .dat
// missing). Codes: `public-suffix/invalid-domain`,
// `public-suffix/not-loaded`.
var PublicSuffixError     = defineClass("PublicSuffixError",     { alwaysPermanent: true });
// MailMdnError — b.mailMdn (lib/mail-mdn.js). RFC 3798 / RFC 8098
// Message Disposition Notification builder + parser violations: bad
// opts at build/parse, malformed multipart/report shape, missing
// required fields (Original-Recipient / Final-Recipient / Disposition),
// disposition / action-mode / sending-mode token allowlist drift,
// auto-generation refusal when the inbound message demanded user
// confirmation (RFC 3798 §2.1) and the operator did not opt in.
// alwaysPermanent — every case is operator-shape or message-shape
// errors that retry will not recover.
var MailMdnError          = defineClass("MailMdnError",          { alwaysPermanent: true });
// ProblemDetailsError — b.problemDetails (lib/problem-details.js). RFC
// 9457 Problem Details for HTTP APIs builder + validator violations:
// bad opts at create/respond/validate, type/title/status/detail/
// instance shape mismatches, reserved-field collision in extensions,
// prototype-pollution-shaped extension keys, bad response object at
// respond(), bad inbound document shape. alwaysPermanent — every case
// is operator-shape or wire-shape errors that retry will not recover.
var ProblemDetailsError   = defineClass("ProblemDetailsError",   { alwaysPermanent: true });
// IdempotencyError — b.middleware.idempotencyKey (lib/middleware/
// idempotency-key.js). draft-ietf-httpapi-idempotency-key middleware
// violations: bad opts at create (missing store, bad ttl, bad methods
// list), bad idempotency key shape (non-string, too long, control
// chars), store-backend transport errors that exhausted retries.
// alwaysPermanent — every operator-facing failure is config-shape;
// transient store-backend failures route through audit signals so
// they don't escape as exceptions to the middleware caller.
var IdempotencyError      = defineClass("IdempotencyError",      { alwaysPermanent: true });

module.exports = {
  FrameworkError:         FrameworkError,
  defineClass:            defineClass,
  MailUnsubscribeError:   MailUnsubscribeError,
  ObjectStoreError:       ObjectStoreError,
  LogStreamError:         LogStreamError,
  QueueError:             QueueError,
  RedisError:             RedisError,
  ExternalDbError:        ExternalDbError,
  ClusterError:           ClusterError,
  ClusterProviderError:   ClusterProviderError,
  HandlerError:           HandlerError,
  StorageError:           StorageError,
  AuthError:              AuthError,
  JobsError:              JobsError,
  SchedulerError:         SchedulerError,
  SessionError:           SessionError,
  SlugError:              SlugError,
  WebhookError:           WebhookError,
  ApiKeyError:            ApiKeyError,
  PermissionsError:       PermissionsError,
  CacheError:             CacheError,
  SeederError:            SeederError,
  I18nError:              I18nError,
  NotifyError:            NotifyError,
  TestingError:           TestingError,
  LockoutError:           LockoutError,
  FileUploadError:        FileUploadError,
  StaticServeError:       StaticServeError,
  GateContractError:      GateContractError,
  GuardCsvError:          GuardCsvError,
  GuardAllError:          GuardAllError,
  GuardHtmlError:         GuardHtmlError,
  GuardSvgError:          GuardSvgError,
  GuardFilenameError:     GuardFilenameError,
  GuardArchiveError:      GuardArchiveError,
  GuardJsonError:         GuardJsonError,
  GuardYamlError:         GuardYamlError,
  GuardXmlError:          GuardXmlError,
  GuardMarkdownError:     GuardMarkdownError,
  GuardEmailError:        GuardEmailError,
  GuardDomainError:       GuardDomainError,
  GuardUuidError:         GuardUuidError,
  GuardCidrError:         GuardCidrError,
  GuardTimeError:         GuardTimeError,
  GuardMimeError:         GuardMimeError,
  GuardJwtError:          GuardJwtError,
  GuardOauthError:        GuardOauthError,
  GuardGraphqlError:      GuardGraphqlError,
  GuardShellError:        GuardShellError,
  GuardRegexError:        GuardRegexError,
  GuardJsonpathError:     GuardJsonpathError,
  GuardTemplateError:     GuardTemplateError,
  GuardImageError:        GuardImageError,
  GuardPdfError:          GuardPdfError,
  GuardAuthError:         GuardAuthError,
  DoraError:              DoraError,
  ComplianceError:        ComplianceError,
  SmtpPolicyError:        SmtpPolicyError,
  MailAuthError:          MailAuthError,
  MailArfError:           MailArfError,
  MailBimiError:          MailBimiError,
  SseError:               SseError,
  McpError:               McpError,
  AiInputError:           AiInputError,
  AiOutputError:          AiOutputError,
  AiPromptError:          AiPromptError,
  A2aError:               A2aError,
  GraphqlFederationError: GraphqlFederationError,
  Fda21Cfr11Error:        Fda21Cfr11Error,
  AuditDailyReviewError:  AuditDailyReviewError,
  AuditSegregationError:  AuditSegregationError,
  DdlChangeControlError:  DdlChangeControlError,
  LegalHoldError:         LegalHoldError,
  WormViolationError:     WormViolationError,
  SandboxError:           SandboxError,
  DlpError:               DlpError,
  AuthBotChallengeError:  AuthBotChallengeError,
  BotChallengeError:      BotChallengeError,
  SessionDeviceBindingError: SessionDeviceBindingError,
  AcmeError:              AcmeError,
  HpkeError:              HpkeError,
  TlsExporterError:       TlsExporterError,
  HttpSigError:           HttpSigError,
  HttpClientError:        HttpClientError,
  KeychainError:          KeychainError,
  WatcherError:           WatcherError,
  LocalDbThinError:       LocalDbThinError,
  RouterError:            RouterError,
  WorkerPoolError:        WorkerPoolError,
  ArgParserError:         ArgParserError,
  DaemonError:            DaemonError,
  SelfUpdateError:        SelfUpdateError,
  FidoMds3Error:          FidoMds3Error,
  PublicSuffixError:      PublicSuffixError,
  MailMdnError:           MailMdnError,
  ProblemDetailsError:    ProblemDetailsError,
  IdempotencyError:       IdempotencyError,
};

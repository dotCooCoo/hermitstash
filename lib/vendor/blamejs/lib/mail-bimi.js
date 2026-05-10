"use strict";
/**
 * @module b.mail.bimi
 * @nav    Mail
 * @title  BIMI
 *
 * @intro
 *   Brand Indicators for Message Identification — RFC 9091. BIMI
 *   records publish a sender's brand-logo URL in DNS so receiving
 *   MTAs can render it next to the message in supported clients
 *   (Gmail, Yahoo, Apple Mail). The TXT record format is:
 *
 *     default._bimi.<domain>  IN  TXT  "v=BIMI1; l=https://...; a=https://..."
 *
 *   - `l=` URL to the SVG logo file (Tiny PS Profile per RFC 9091 §5)
 *   - `a=` URL to the Verified Mark Certificate (VMC / CMC) — §6
 *
 *   BIMI is layered on a passing DMARC posture (the receiver requires
 *   DMARC at quarantine or reject). No-op for senders without DMARC
 *   enforcement.
 *
 *   Surface:
 *
 *     b.mail.bimi.recordShape({ logoUrl, vmcUrl?, selector? })  -> string
 *     b.mail.bimi.fetchPolicy(domain, opts?)                    -> record | null
 *     b.mail.bimi.parseRecord(text)                             -> record | null
 *     b.mail.bimi.fetchAndVerifyMark({ domain, vmcUrl, ... })   -> verified mark
 *     b.mail.bimi.validateTinyPsSvg(svgBytes)                   -> { ok, violations }
 *
 *   `fetchAndVerifyMark` fetches a VMC / CMC over HTTPS via b.httpClient,
 *   parses it as X.509, validates the chain against the BIMI Group
 *   trust anchors (vendored at lib/vendor/bimi-trust-anchors.pem,
 *   operator-overridable via `trustAnchorsPem`), confirms the cert's
 *   subjectAltName URI matches the BIMI domain, and confirms the
 *   cert carries the BIMI mark-verification policy OID
 *   (1.3.6.1.5.5.7.3.31). The verified mark is returned as
 *   { svg, evidenceDocument } pulled from RFC 3709 logotype extension
 *   when present.
 *
 *   `validateTinyPsSvg` enforces the AuthIndicators-WG Tiny PS subset:
 *   single root <svg>, version="1.2", baseProfile="tiny-ps", viewBox
 *   present, no script / style / foreignObject / animate / filter /
 *   image, no external href / xlink:href references (only #fragment
 *   permitted), bounded byte size (32 KiB cap).
 *
 * @card
 *   RFC 9091 BIMI policy lookup, VMC + CMC fetch + chain validation, and Tiny-PS SVG profile enforcement for inbox brand-mark rendering.
 */

var dns = require("node:dns");
var nodeCrypto = require("node:crypto");
var dnsPromises = dns.promises;
var fs = require("node:fs");
var nodePath = require("node:path");

var asn1 = require("./asn1-der");
var C = require("./constants");
var httpClient = require("./http-client");
var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var { defineClass, MailBimiError } = require("./framework-error");

// Audit emitter — lazy to avoid pulling the audit dispatcher into the
// module load graph until the first verify call. fetchAndVerifyMark is
// the only path that emits.
var audit = lazyRequire(function () { return require("./audit"); });

// Pre-existing BimiError covered DNS / record-shape failures. Kept for
// backwards-compatibility on the existing surface (recordShape /
// parseRecord / fetchPolicy). The new fetchAndVerifyMark / Tiny-PS
// surface uses MailBimiError so chain / policy / SVG failures route
// to a domain-shared class with the documented `bimi/...` codes.
var BimiError = defineClass("BimiError", { alwaysPermanent: true });

var BIMI_VERSION = "BIMI1";
var BIMI_DEFAULT_SELECTOR = "default";
var BIMI_RECORD_MAX_BYTES = C.BYTES.kib(2);

// AuthIndicators-WG Tiny-PS profile cap (32 KiB). Larger SVGs are
// refused at validate-time before any tokenization.
var TINY_PS_MAX_BYTES = C.BYTES.kib(32);

// VMC / CMC fetch cap. Production VMCs are typically ~10-20 KiB;
// 256 KiB is a generous ceiling that still bounds the download against
// pathological responses. Operators with a stricter posture pass
// `maxResponseBytes` to override.
var VMC_DEFAULT_MAX_BYTES = C.BYTES.kib(256);

// HTTP timeout for the VMC / CMC fetch. Operators pass `timeoutMs` to
// override.
var VMC_DEFAULT_TIMEOUT_MS = C.TIME.seconds(15);

// RFC 9091 6.1.1 — the BIMI mark-verification ExtendedKeyUsage OID.
// A valid VMC / CMC MUST list this OID under id-ce-extKeyUsage
// (2.5.29.37). The OID is identical for both certificate types; the
// distinction between VMC and CMC is conveyed by the cert's policyOIDs
// (id-ce-certificatePolicies, 2.5.29.32):
//
//   1.3.6.1.5.5.7.3.31     - id-kp-bimi (Mark Verification)
//   1.3.6.1.4.1.53087.1.1  - VMC policy (registered trademark)
//   1.3.6.1.4.1.53087.1.2  - CMC policy (common mark, prior-use)
//
// The framework verifies the EKU OID is present; the policy OIDs are
// surfaced on the result so operators can branch their UI on
// VMC-vs-CMC if their inbox renders them differently.
var BIMI_EKU_MARK_VERIFICATION = "1.3.6.1.5.5.7.3.31";
var VMC_POLICY_OID = "1.3.6.1.4.1.53087.1.1";
var CMC_POLICY_OID = "1.3.6.1.4.1.53087.1.2";

// RFC 3709 4.2 — the logotype extension OID.
var ID_PE_LOGOTYPE = "1.3.6.1.5.5.7.1.12";

// Vendored BIMI Group trust anchors. Read once at module load. The
// vendor file may be empty-of-PEM in source trees (operators populate
// via the documented refresh procedure); fetchAndVerifyMark refuses
// to validate if both the vendored bundle is empty and the call-site
// `trustAnchorsPem` opt is absent.
var _vendoredTrustAnchorsPath = nodePath.join(__dirname, "vendor", "bimi-trust-anchors.pem");
var _vendoredTrustAnchorsPem = "";
try {
  _vendoredTrustAnchorsPem = fs.readFileSync(_vendoredTrustAnchorsPath, "utf8");
} catch (_e) {
  _vendoredTrustAnchorsPem = "";
}

function _validateUrl(url, label) {
  // RFC 9091 4.2 — `l=` and `a=` MUST be HTTPS URLs.
  try {
    safeUrl.parse(url, { allowedProtocols: ["https:"] });
  } catch (e) {
    throw new BimiError("mail-bimi/bad-" + label,
      "bimi: " + label + " must be an https:// URL - got '" + url + "': " +
      ((e && e.message) || String(e)));
  }
}

/**
 * @primitive b.mail.bimi.recordShape
 * @signature b.mail.bimi.recordShape(opts)
 * @since     0.7.0
 * @status    stable
 * @related   b.mail.bimi.parseRecord, b.mail.bimi.fetchPolicy
 *
 * Builds the canonical RFC 9091 BIMI TXT-record string from a logo
 * URL and optional VMC URL. Throws on missing or non-https URLs and
 * on control / record-separator characters in the URLs. Operators
 * publish the returned string at `default._bimi.<domain>` (or the
 * selector subdomain if they're using non-default selectors).
 *
 * @opts
 *   {
 *     logoUrl:   string,    // required - https:// URL to Tiny-PS SVG
 *     vmcUrl:    string?,   // optional - https:// URL to VMC / CMC PEM
 *     selector:  string?,   // unused at record-shape time; reserved
 *                           //   for future per-selector behavior
 *   }
 *
 * @example
 *   var rec = b.mail.bimi.recordShape({
 *     logoUrl: "https://example.com/bimi/logo.svg",
 *     vmcUrl:  "https://example.com/bimi/cert.pem",
 *   });
 *   // -> "v=BIMI1; l=https://example.com/bimi/logo.svg; a=https://example.com/bimi/cert.pem"
 */
function recordShape(opts) {
  validateOpts.requireObject(opts, "bimi.recordShape", BimiError);
  validateOpts(opts, ["logoUrl", "vmcUrl", "selector"], "bimi.recordShape");
  validateOpts.requireNonEmptyString(opts.logoUrl,
    "bimi.recordShape: logoUrl", BimiError, "mail-bimi/no-logo");
  _validateUrl(opts.logoUrl, "logoUrl");
  if (opts.vmcUrl !== undefined && opts.vmcUrl !== null) {
    validateOpts.requireNonEmptyString(opts.vmcUrl,
      "bimi.recordShape: vmcUrl", BimiError, "mail-bimi/bad-vmc");
    _validateUrl(opts.vmcUrl, "vmcUrl");
  }
  // No CR/LF/NUL/semicolon - defense-in-depth so a hostile URL can't
  // inject a record-separator sequence into the published TXT.
  if (/[\r\n\0;]/.test(opts.logoUrl)) {
    throw new BimiError("mail-bimi/bad-logo",
      "bimi.recordShape: logoUrl contains forbidden control / record-separator characters");
  }
  if (opts.vmcUrl && /[\r\n\0;]/.test(opts.vmcUrl)) {
    throw new BimiError("mail-bimi/bad-vmc",
      "bimi.recordShape: vmcUrl contains forbidden control / record-separator characters");
  }

  var fields = ["v=" + BIMI_VERSION, "l=" + opts.logoUrl];
  if (opts.vmcUrl) fields.push("a=" + opts.vmcUrl);
  return fields.join("; ");
}

/**
 * @primitive b.mail.bimi.parseRecord
 * @signature b.mail.bimi.parseRecord(text)
 * @since     0.7.0
 * @status    stable
 * @related   b.mail.bimi.fetchPolicy
 *
 * Parses a BIMI TXT record into `{ v, l, a }`. Returns null when the
 * text is not a v=BIMI1 record, the `l=` URL is missing, or the
 * total bytes exceed the 2 KiB sanity cap. Use this when the operator
 * already has the TXT bytes in hand (e.g. an inbound auth-results
 * pipeline carrying the resolved record).
 *
 * @example
 *   var rv = b.mail.bimi.parseRecord("v=BIMI1; l=https://example.com/logo.svg");
 *   // -> { v: "BIMI1", l: "https://example.com/logo.svg", a: null }
 */
function parseRecord(text) {
  if (typeof text !== "string" || text.length === 0) return null;
  if (text.length > BIMI_RECORD_MAX_BYTES) return null;
  // RFC 9091 4 - semicolon-separated, key=value, leading "v=BIMI1".
  var parts = text.split(";");
  var rv = { v: null, l: null, a: null };
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i].trim();
    if (p.length === 0) continue;
    var eq = p.indexOf("=");
    if (eq === -1) continue;
    var k = p.slice(0, eq).trim().toLowerCase();
    var v = p.slice(eq + 1).trim();
    if (k === "v" || k === "l" || k === "a") rv[k] = v;
  }
  if (rv.v !== BIMI_VERSION || !rv.l) return null;
  return rv;
}

/**
 * @primitive b.mail.bimi.fetchPolicy
 * @signature b.mail.bimi.fetchPolicy(domain, opts?)
 * @since     0.7.0
 * @status    stable
 * @related   b.mail.bimi.fetchAndVerifyMark
 *
 * Resolves `default._bimi.<domain>` (or `<selector>._bimi.<domain>`
 * if `opts.selector` is set) and returns the parsed `{ v, l, a }`.
 * Returns null when no TXT record exists or no record on the
 * resolved name parses as v=BIMI1. Operators feed the returned
 * `l=` / `a=` URLs into `fetchAndVerifyMark` to retrieve the
 * verified mark.
 *
 * @opts
 *   {
 *     selector:  string?,                       // default "default"
 *     dnsLookup: async (qname, type) => rows?,  // operator-supplied resolver
 *                                               //   (DoH / cache / fixture);
 *                                               //   default: node:dns.resolveTxt
 *   }
 *
 * @example
 *   var pol = await b.mail.bimi.fetchPolicy("example.com");
 *   if (pol && pol.a) {
 *     var verified = await b.mail.bimi.fetchAndVerifyMark({
 *       domain:  "example.com",
 *       vmcUrl:  pol.a,
 *     });
 *   }
 */
async function fetchPolicy(domain, opts) {
  validateOpts.requireNonEmptyString(domain,
    "bimi.fetchPolicy: domain", BimiError, "mail-bimi/bad-domain");
  opts = opts || {};
  var selector = opts.selector || BIMI_DEFAULT_SELECTOR;
  var qname = selector + "._bimi." + domain;
  var records;
  try {
    if (opts.dnsLookup) records = await opts.dnsLookup(qname, "TXT");
    else records = await dnsPromises.resolveTxt(qname);
  } catch (e) {
    if (e && (e.code === "ENOTFOUND" || e.code === "ENODATA")) return null;
    throw new BimiError("mail-bimi/lookup-failed",
      "bimi.fetchPolicy: TXT lookup for " + qname + " failed: " +
      ((e && e.message) || String(e)));
  }
  // RFC 9091 4.1 - a TXT lookup may return multiple chunks; pick
  // the first record that begins with v=BIMI1.
  for (var i = 0; i < (records || []).length; i += 1) {
    var rec = records[i];
    var s = Array.isArray(rec) ? rec.join("") : String(rec);
    var parsed = parseRecord(s);
    if (parsed) return parsed;
  }
  return null;
}

// ---- Tiny-PS SVG validation ----

// AuthIndicators-WG Tiny PS Profile 3 - refused element list. Each
// element here is an unconditional refuse: <script> enables JS
// execution, <style> carries CSS that can fetch external resources,
// <foreignObject> tunnels arbitrary HTML / XML, animation elements
// trigger time-based DOM changes (security + battery), <filter>
// requires a non-trivial renderer, <image> re-fetches arbitrary URLs
// (SSRF vector inside the inbox preview pipeline).
var TINY_PS_FORBIDDEN_TAGS = {
  "script": true,
  "style": true,
  "foreignobject": true,
  "animate": true,
  "animatetransform": true,
  "animatemotion": true,
  "set": true,
  "filter": true,
  "image": true,
};

/**
 * @primitive b.mail.bimi.validateTinyPsSvg
 * @signature b.mail.bimi.validateTinyPsSvg(svgBytes)
 * @since     0.8.53
 * @status    stable
 * @related   b.mail.bimi.fetchAndVerifyMark, b.guardSvg
 *
 * Validates a brand-mark SVG against the AuthIndicators-WG Tiny PS
 * profile (RFC 9091 5). Tiny-PS is a strict subset of SVG 1.2:
 * single <svg> root with `version="1.2"` and `baseProfile="tiny-ps"`,
 * `viewBox` required, byte size up to 32 KiB, no scripts / styles /
 * foreign content / animation / filters / external image refs, no
 * external references in `href` / `xlink:href` attributes (only
 * `#fragment` permitted), no `<!DOCTYPE>` / `<!ENTITY>` / processing
 * instructions other than the XML prolog. Returns
 * `{ ok, violations }` where each violation is `{ code, message }`.
 * Throws `MailBimiError` (`bimi/svg-too-large`) when the input
 * exceeds the byte cap; throws (`bimi/svg-tiny-ps-violation` with
 * `parse-failed`) on tokenizer failure.
 *
 * @opts
 *   svgBytes: Buffer | string
 *
 * @example
 *   var rv = b.mail.bimi.validateTinyPsSvg('<svg version="1.2" baseProfile="tiny-ps" viewBox="0 0 1 1" xmlns="http://www.w3.org/2000/svg"></svg>');
 *   // -> { ok: true, violations: [] }
 */
function validateTinyPsSvg(svgBytes) {
  var s;
  if (Buffer.isBuffer(svgBytes) || svgBytes instanceof Uint8Array) {
    if (svgBytes.length > TINY_PS_MAX_BYTES) {
      throw new MailBimiError("bimi/svg-too-large",
        "bimi.validateTinyPsSvg: input " + svgBytes.length + " bytes exceeds Tiny-PS cap " + TINY_PS_MAX_BYTES);
    }
    s = safeBuffer.normalizeText(Buffer.from(svgBytes), {
      maxBytes:    TINY_PS_MAX_BYTES,
      errorClass:  MailBimiError,
      typeCode:    "bimi/svg-tiny-ps-violation",
      sizeCode:    "bimi/svg-too-large",
      typeMessage: "bimi.validateTinyPsSvg: input must be Buffer / Uint8Array / string",
      sizeMessage: "bimi.validateTinyPsSvg: input exceeds Tiny-PS cap " + TINY_PS_MAX_BYTES + " bytes",
    });
  } else if (typeof svgBytes === "string") {
    if (Buffer.byteLength(svgBytes, "utf8") > TINY_PS_MAX_BYTES) {
      throw new MailBimiError("bimi/svg-too-large",
        "bimi.validateTinyPsSvg: input " + Buffer.byteLength(svgBytes, "utf8") + " bytes exceeds Tiny-PS cap " + TINY_PS_MAX_BYTES);
    }
    s = svgBytes;
  } else {
    throw new MailBimiError("bimi/svg-tiny-ps-violation",
      "bimi.validateTinyPsSvg: input must be Buffer / Uint8Array / string");
  }

  var violations = [];
  function _vio(code, message) { violations.push({ code: code, message: message }); }

  var tokens;
  try { tokens = _tokenizeTinyPsSvg(s); }
  catch (e) {
    throw new MailBimiError("bimi/svg-tiny-ps-violation",
      "bimi.validateTinyPsSvg: parse-failed: " + ((e && e.message) || String(e)));
  }

  var rootSvg = null;
  var depth = 0;
  var sawSecondRoot = false;
  for (var i = 0; i < tokens.length; i += 1) {
    var t = tokens[i];

    if (t.type === "doctype") {
      _vio("doctype-forbidden", "<!DOCTYPE> is forbidden in Tiny-PS (entity-expansion / DTD class)");
      continue;
    }
    if (t.type === "declaration") {
      _vio("declaration-forbidden",
        "<!" + (t.raw || "").slice(2, 30) + "...> declaration is forbidden in Tiny-PS");
      continue;
    }
    if (t.type === "processingInstruction") {
      var pir = (t.raw || "").trim();
      if (!/^<\?xml\b/i.test(pir)) {
        _vio("pi-forbidden", "processing instruction is forbidden in Tiny-PS: " + pir.slice(0, 40))   /* allow:raw-byte-literal — display truncation chars, not bytes */;
      }
      continue;
    }
    if (t.type === "comment" || t.type === "text" || t.type === "cdata") continue;

    if (t.type === "endTag") {
      depth -= 1;
      continue;
    }

    if (t.type === "tag") {
      var name = t.name;
      if (TINY_PS_FORBIDDEN_TAGS[name]) {
        _vio("element-forbidden",
          "<" + name + "> is forbidden in Tiny-PS (script / style / animation / filter / image / foreign-content class)");
      }
      // Any element name starting with "animate" is animation (covers
      // future SMIL extensions not in the static list above).
      if (name.indexOf("animate") === 0 && !TINY_PS_FORBIDDEN_TAGS[name]) {
        _vio("element-forbidden",
          "<" + name + "> animation element is forbidden in Tiny-PS");
      }

      // Top-level root tracking. The root <svg> MUST be at depth 0; any
      // second top-level element is a multi-root violation.
      if (depth === 0) {
        if (rootSvg === null) {
          if (name !== "svg") {
            _vio("root-not-svg",
              "Tiny-PS root element must be <svg> - got <" + name + ">");
          }
          rootSvg = t;
        } else if (!sawSecondRoot) {
          _vio("multiple-root-elements",
            "Tiny-PS document must have exactly one root <svg> element");
          sawSecondRoot = true;
        }
      }

      var attrs = t.attrs || {};
      for (var aname in attrs) {
        if (!Object.prototype.hasOwnProperty.call(attrs, aname)) continue;
        var aval = String(attrs[aname]);
        var lname = aname.toLowerCase();

        // Event-handler attrs (onload / onclick / on*) - universally
        // forbidden; same JS-execution class as <script>.
        if (lname.indexOf("on") === 0 && lname.length > 2) {
          _vio("event-handler-forbidden",
            "event-handler attribute `" + aname + "` is forbidden in Tiny-PS");
        }

        // href / xlink:href - only #fragment refs allowed.
        if (lname === "href" || lname === "xlink:href") {
          if (aval.length > 0 && aval.charAt(0) !== "#") {
            _vio("external-ref-forbidden",
              "external reference in `" + aname + "='" + aval.slice(0, 60) /* allow:raw-time-literal — display truncation chars, not seconds */ + "...'` " +
              "is forbidden in Tiny-PS (only `#fragment` permitted)");
          }
        }

        // style attribute - Tiny-PS forbids <style>; the style attribute
        // is treated as the same risk surface (CSS @import / url() class).
        if (lname === "style") {
          _vio("style-attr-forbidden",
            "`style` attribute is forbidden in Tiny-PS (CSS @import / url() class)");
        }
      }

      if (!t.selfClosing) depth += 1;
    }
  }

  if (rootSvg !== null) {
    var rootAttrs = rootSvg.attrs || {};
    if (rootAttrs.version !== "1.2") {
      _vio("bad-version",
        "Tiny-PS requires version=\"1.2\" on root <svg> - got `" +
        (rootAttrs.version === undefined ? "(missing)" : rootAttrs.version) + "`");
    }
    if (rootAttrs.baseProfile !== "tiny-ps" && rootAttrs.baseprofile !== "tiny-ps") {
      _vio("bad-base-profile",
        "Tiny-PS requires baseProfile=\"tiny-ps\" on root <svg> - got `" +
        (rootAttrs.baseProfile || rootAttrs.baseprofile || "(missing)") + "`");
    }
    if (!rootAttrs.viewBox && !rootAttrs.viewbox) {
      _vio("missing-viewbox",
        "Tiny-PS requires viewBox attribute on root <svg>");
    }
  }

  return { ok: violations.length === 0, violations: violations };
}

// _tokenizeTinyPsSvg - minimal SVG tokenizer for Tiny-PS profile checks.
// Same shape as guard-svg's tokenizer but tighter (Tiny-PS only needs
// element / attribute / declaration shapes; no sanitization output).
function _tokenizeTinyPsSvg(s) {
  var tokens = [];
  var len = s.length;
  var pos = 0;

  while (pos < len) {
    var lt = s.indexOf("<", pos);
    if (lt === -1) {
      if (pos < len) tokens.push({ type: "text", raw: s.slice(pos, len) });
      break;
    }
    if (lt > pos) tokens.push({ type: "text", raw: s.slice(pos, lt) });

    if (s.startsWith("<!--", lt)) {
      var endC = s.indexOf("-->", lt + 4);
      if (endC === -1) throw new Error("unterminated comment");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      tokens.push({ type: "comment", raw: s.slice(lt, endC + 3) });
      pos = endC + 3;
      continue;
    }
    if (s.startsWith("<![CDATA[", lt)) {
      var endX = s.indexOf("]]>", lt + 9);
      if (endX === -1) throw new Error("unterminated CDATA");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      tokens.push({ type: "cdata", raw: s.slice(lt, endX + 3) });
      pos = endX + 3;
      continue;
    }
    if (s.startsWith("<!DOCTYPE", lt) || s.startsWith("<!doctype", lt)) {
      var endD = s.indexOf(">", lt);
      if (endD === -1) throw new Error("unterminated doctype");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      tokens.push({ type: "doctype", raw: s.slice(lt, endD + 1) });
      pos = endD + 1;
      continue;
    }
    if (s.charAt(lt + 1) === "?") {
      var endP = s.indexOf("?>", lt + 2);
      if (endP === -1) throw new Error("unterminated processing instruction");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      tokens.push({ type: "processingInstruction", raw: s.slice(lt, endP + 2) });
      pos = endP + 2;
      continue;
    }
    if (s.charAt(lt + 1) === "!") {
      var endDecl = s.indexOf(">", lt);
      if (endDecl === -1) throw new Error("unterminated declaration");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      tokens.push({ type: "declaration", raw: s.slice(lt, endDecl + 1) });
      pos = endDecl + 1;
      continue;
    }
    if (s.charAt(lt + 1) === "/") {
      var endE = s.indexOf(">", lt);
      if (endE === -1) throw new Error("unterminated end tag");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
      var ename = s.slice(lt + 2, endE).trim().toLowerCase().split(/\s/)[0];
      tokens.push({ type: "endTag", name: ename });
      pos = endE + 1;
      continue;
    }

    var pp = lt + 1;
    var inQuote = "";
    while (pp < len) {
      var ch = s.charAt(pp);
      if (inQuote) {
        if (ch === inQuote) inQuote = "";
      } else {
        if (ch === '"' || ch === "'") inQuote = ch;
        else if (ch === ">") break;
      }
      pp += 1;
    }
    if (pp >= len) throw new Error("unterminated start tag");   // allow:bare-error-throw — caught by outer try/catch and re-thrown as MailBimiError("bimi/svg-tiny-ps-violation")
    var raw = s.slice(lt, pp + 1);
    var inner = raw.slice(1, raw.length - 1);
    var selfClosing = inner.endsWith("/");
    if (selfClosing) inner = inner.slice(0, inner.length - 1);

    var nameMatch = inner.match(/^([A-Za-z][A-Za-z0-9:_-]*)/);
    var tagName = nameMatch ? nameMatch[1].toLowerCase() : "";
    var attrSrc = nameMatch ? inner.slice(nameMatch[0].length) : "";

    tokens.push({
      type:        "tag",
      name:        tagName,
      attrs:       _parseTinyPsAttrs(attrSrc),
      raw:         raw,
      selfClosing: selfClosing,
    });
    pos = pp + 1;
  }
  return tokens;
}

// _parseTinyPsAttrs - quoted-only attribute parser. Tiny-PS values are
// typically quoted in well-formed XML; bare-token / single-quoted
// values are still accepted (the SVG profile is permissive on quoting).
function _parseTinyPsAttrs(src) {
  var attrs = {};
  var re = /([A-Za-z_:][A-Za-z0-9:._-]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/g;
  var m;
  while ((m = re.exec(src)) !== null) {
    var name = m[1];
    var value = m[3] !== undefined ? m[3] : (m[4] !== undefined ? m[4] : (m[5] || ""));
    attrs[name] = value;
  }
  return attrs;
}

// ---- VMC / CMC fetch + chain validation ----

/**
 * @primitive b.mail.bimi.fetchAndVerifyMark
 * @signature b.mail.bimi.fetchAndVerifyMark(opts)
 * @since     0.8.53
 * @status    stable
 * @related   b.mail.bimi.fetchPolicy, b.mail.bimi.validateTinyPsSvg
 *
 * Fetches a VMC / CMC PEM from `opts.vmcUrl` (or `opts.cmcUrl`) over
 * HTTPS, parses it as X.509, validates the chain against the BIMI
 * Group trust anchors (vendored at lib/vendor/bimi-trust-anchors.pem,
 * operator-overridable via `trustAnchorsPem`), confirms the cert's
 * subjectAltName URI matches the BIMI domain, and confirms the cert
 * carries the BIMI mark-verification ExtendedKeyUsage OID
 * (1.3.6.1.5.5.7.3.31). Returns
 * `{ ok, mark, certificate, vmcType }` where `vmcType` is `"vmc"`
 * or `"cmc"` derived from the cert's policyOIDs, and `mark` carries
 * the SVG bytes when the cert's RFC 3709 logotype extension is
 * present (or null when not). Throws `MailBimiError` with one of
 * the documented codes on any failure.
 *
 * @opts
 *   {
 *     domain:            string,       // required - BIMI domain to assert
 *                                      //   matches subjectAltName URI
 *     vmcUrl:            string?,      // VMC PEM URL (https://); operator
 *                                      //   passes one of vmcUrl / cmcUrl
 *     cmcUrl:            string?,      // CMC PEM URL (https://); same
 *     trustAnchorsPem:   string?,      // operator-supplied PEM bundle;
 *                                      //   defaults to the vendored
 *                                      //   bimi-trust-anchors.pem
 *     timeoutMs:         number?,      // default 15s
 *     maxResponseBytes:  number?,      // default 256 KiB
 *     audit:             { safeEmit }, // operator-supplied audit dispatcher
 *     httpClient:        object?,      // default b.httpClient - test-only
 *                                      //   override for unit tests that
 *                                      //   want to stub the network call
 *     evidenceDocument:  string?,      // operator-supplied trademark
 *                                      //   evidence URL; surfaced on
 *                                      //   the result for audit logging
 *   }
 *
 * @example
 *   var rv = await b.mail.bimi.fetchAndVerifyMark({
 *     domain:           "example.com",
 *     vmcUrl:           "https://example.com/bimi/cert.pem",
 *     trustAnchorsPem:  "-----BEGIN CERTIFICATE-----\n...",
 *   });
 *   // -> { ok, mark: { svg, evidenceDocument }, certificate, vmcType: "vmc" }
 */
async function fetchAndVerifyMark(opts) {
  validateOpts.requireObject(opts, "bimi.fetchAndVerifyMark", MailBimiError, "bimi/bad-opts");
  validateOpts(opts, [
    "domain", "vmcUrl", "cmcUrl",
    "trustAnchorsPem", "timeoutMs", "maxResponseBytes",
    "audit", "httpClient", "evidenceDocument",
  ], "bimi.fetchAndVerifyMark");
  validateOpts.requireNonEmptyString(opts.domain,
    "bimi.fetchAndVerifyMark: domain", MailBimiError, "bimi/bad-opts");

  var url = opts.vmcUrl || opts.cmcUrl;
  if (typeof url !== "string" || url.length === 0) {
    throw new MailBimiError("bimi/bad-opts",
      "bimi.fetchAndVerifyMark: one of vmcUrl / cmcUrl is required");
  }
  // RFC 9091 6 - cert URL MUST be https.
  try { safeUrl.parse(url, { allowedProtocols: ["https:"] }); }
  catch (e) {
    throw new MailBimiError("bimi/bad-opts",
      "bimi.fetchAndVerifyMark: cert URL must be https - got `" + url + "`: " +
      ((e && e.message) || String(e)));
  }

  var timeoutMs = opts.timeoutMs !== undefined ? opts.timeoutMs : VMC_DEFAULT_TIMEOUT_MS;
  var maxBytes  = opts.maxResponseBytes !== undefined ? opts.maxResponseBytes : VMC_DEFAULT_MAX_BYTES;

  var hc = opts.httpClient || httpClient;

  var rsp;
  try {
    rsp = await hc.request({
      method:           "GET",
      url:              url,
      timeoutMs:        timeoutMs,
      maxResponseBytes: maxBytes,
      allowedProtocols: ["https:"],
      headers:          { "Accept": "application/x-pem-file, application/pem-certificate-chain, text/plain" },
      errorClass:       MailBimiError,
    });
  } catch (e) {
    _emitAudit(opts, "mail.bimi.vmc.fetched", "failure",
      { url: url, domain: opts.domain, reason: (e && e.message) || String(e) });
    throw new MailBimiError("bimi/vmc-fetch-failed",
      "bimi.fetchAndVerifyMark: GET " + url + " failed: " + ((e && e.message) || String(e)));
  }
  if (rsp.statusCode !== 200) {
    _emitAudit(opts, "mail.bimi.vmc.fetched", "failure",
      { url: url, domain: opts.domain, status: rsp.statusCode });
    throw new MailBimiError("bimi/vmc-fetch-failed",
      "bimi.fetchAndVerifyMark: GET " + url + " returned status " + rsp.statusCode);
  }
  var pemBytes = Buffer.isBuffer(rsp.body) ? rsp.body.toString("utf8") : String(rsp.body || "");
  if (pemBytes.indexOf("-----BEGIN CERTIFICATE-----") === -1) {
    _emitAudit(opts, "mail.bimi.vmc.fetched", "failure",
      { url: url, domain: opts.domain, reason: "no-pem" });
    throw new MailBimiError("bimi/vmc-fetch-failed",
      "bimi.fetchAndVerifyMark: response body is not a PEM-encoded CERTIFICATE chain");
  }

  var certPems = _splitPemChain(pemBytes);
  if (certPems.length === 0) {
    throw new MailBimiError("bimi/vmc-fetch-failed",
      "bimi.fetchAndVerifyMark: no CERTIFICATE blocks in PEM body");
  }
  var leaf;
  var intermediates = [];
  try {
    leaf = new nodeCrypto.X509Certificate(certPems[0]);
    for (var i = 1; i < certPems.length; i += 1) {
      intermediates.push(new nodeCrypto.X509Certificate(certPems[i]));
    }
  } catch (e) {
    throw new MailBimiError("bimi/vmc-chain-invalid",
      "bimi.fetchAndVerifyMark: X.509 parse failed: " + ((e && e.message) || String(e)));
  }

  var trustAnchorsPem = typeof opts.trustAnchorsPem === "string" && opts.trustAnchorsPem.length > 0
    ? opts.trustAnchorsPem
    : _vendoredTrustAnchorsPem;
  var anchorPems = _splitPemChain(trustAnchorsPem);
  if (anchorPems.length === 0) {
    throw new MailBimiError("bimi/vmc-chain-invalid",
      "bimi.fetchAndVerifyMark: no trust anchors configured - populate " +
      "lib/vendor/bimi-trust-anchors.pem or pass `trustAnchorsPem` " +
      "(see RFC 9091 6 / BIMI Group VMC issuer list)");
  }
  var anchors;
  try {
    anchors = anchorPems.map(function (p) { return new nodeCrypto.X509Certificate(p); });
  } catch (e) {
    throw new MailBimiError("bimi/vmc-chain-invalid",
      "bimi.fetchAndVerifyMark: trust-anchor PEM parse failed: " + ((e && e.message) || String(e)));
  }
  var chainOk = _verifyCertChain(leaf, intermediates, anchors);
  if (!chainOk.ok) {
    _emitAudit(opts, "mail.bimi.vmc.verified", "failure",
      { url: url, domain: opts.domain, reason: chainOk.reason });
    throw new MailBimiError("bimi/vmc-chain-invalid",
      "bimi.fetchAndVerifyMark: chain validation failed: " + chainOk.reason);
  }

  var sanMatch = _subjectAltNameMatchesDomain(leaf, opts.domain);
  if (!sanMatch.ok) {
    _emitAudit(opts, "mail.bimi.vmc.verified", "failure",
      { url: url, domain: opts.domain, reason: "san-mismatch", san: sanMatch.found });
    throw new MailBimiError("bimi/vmc-domain-mismatch",
      "bimi.fetchAndVerifyMark: subjectAltName does not include BIMI domain `" +
      opts.domain + "` - found: " + (sanMatch.found.length === 0 ? "(none)" : sanMatch.found.join(", ")));
  }

  var policyInfo = _extractBimiCertPolicy(leaf);
  if (!policyInfo.hasMarkVerificationEku) {
    _emitAudit(opts, "mail.bimi.vmc.verified", "failure",
      { url: url, domain: opts.domain, reason: "missing-eku" });
    throw new MailBimiError("bimi/vmc-policy-oid-missing",
      "bimi.fetchAndVerifyMark: certificate is missing the BIMI mark-verification " +
      "ExtendedKeyUsage OID (" + BIMI_EKU_MARK_VERIFICATION + ") - RFC 9091 6.1.1");
  }

  var vmcType = "vmc";
  if (policyInfo.policyOids.indexOf(CMC_POLICY_OID) !== -1 &&
      policyInfo.policyOids.indexOf(VMC_POLICY_OID) === -1) {
    vmcType = "cmc";
  }

  var mark = {
    svg:               policyInfo.logoSvg,
    evidenceDocument:  typeof opts.evidenceDocument === "string" ? opts.evidenceDocument : null,
  };

  _emitAudit(opts, "mail.bimi.vmc.verified", "success", {
    url:      url,
    domain:   opts.domain,
    vmcType:  vmcType,
    issuer:   leaf.issuer,
    subject:  leaf.subject,
    notAfter: leaf.validTo,
  });

  return {
    ok: true,
    mark: mark,
    certificate: {
      issuer:     leaf.issuer,
      subject:    leaf.subject,
      notAfter:   leaf.validTo,
      notBefore:  leaf.validFrom,
      policyOids: policyInfo.policyOids.slice(),
    },
    vmcType: vmcType,
  };
}

// ---- helpers (chain validation, PEM parsing, ASN.1 OID walks) ----

function _splitPemChain(pemText) {
  if (typeof pemText !== "string") return [];
  var out = [];
  var re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  var m;
  while ((m = re.exec(pemText)) !== null) out.push(m[0]);
  return out;
}

// _verifyCertChain - best-effort path validation using node:crypto
// X509Certificate.verify(publicKey) for signature verification, plus
// checkIssued() for issuer-DN matching and notBefore / notAfter for
// validity windows.
function _verifyCertChain(leaf, intermediates, anchors) {
  var now = Date.now();
  var current = leaf;
  var depth = 0;
  // Realistic VMC chains are leaf -> intermediate -> root (depth 2).
  // 8 is a generous upper bound that prevents pathological loops.
  var MAX_DEPTH = 8;

  while (depth < MAX_DEPTH) {
    var notBefore = Date.parse(current.validFrom);
    var notAfter  = Date.parse(current.validTo);
    if (isFinite(notBefore) && now < notBefore) {
      return { ok: false, reason: "cert not-yet-valid (notBefore=" + current.validFrom + ")" };
    }
    if (isFinite(notAfter) && now > notAfter) {
      return { ok: false, reason: "cert expired (notAfter=" + current.validTo + ")" };
    }

    for (var ai = 0; ai < anchors.length; ai += 1) {
      var anchor = anchors[ai];
      if (current.checkIssued(anchor)) {
        try {
          if (current.verify(anchor.publicKey)) return { ok: true };
        } catch (_e) { /* fall through to next anchor */ }
      }
    }
    if (current.checkIssued(current)) {
      return { ok: false, reason: "self-signed root not in trust-anchor bundle" };
    }

    var nextIssuer = null;
    for (var ii = 0; ii < intermediates.length; ii += 1) {
      var cand = intermediates[ii];
      if (cand === current) continue;
      if (current.checkIssued(cand)) {
        try {
          if (current.verify(cand.publicKey)) {
            nextIssuer = cand;
            break;
          }
        } catch (_e) { /* fall through */ }
      }
    }
    if (nextIssuer === null) {
      return { ok: false, reason: "no issuer found for `" + current.subject + "` in chain or trust anchors" };
    }
    current = nextIssuer;
    depth += 1;
  }
  return { ok: false, reason: "chain depth exceeded " + MAX_DEPTH };
}

// _subjectAltNameMatchesDomain - RFC 9091 6 mandates a URI-form SAN
// pointing at the BIMI domain. Node's X509Certificate.subjectAltName
// is a comma-separated string like "URI:https://example.com, DNS:example.com";
// accept either a URI:* matching the domain's hostname OR a DNS:*
// exact match (compat - some VMC profiles emit DNS instead of URI).
function _subjectAltNameMatchesDomain(cert, domain) {
  var raw = cert.subjectAltName || "";
  var parts = raw.split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  var found = parts.slice();
  var dom = domain.toLowerCase();
  for (var i = 0; i < parts.length; i += 1) {
    var p = parts[i];
    var lp = p.toLowerCase();
    if (lp.indexOf("dns:") === 0) {
      var dns2 = lp.slice(4);
      if (dns2 === dom) return { ok: true, found: found };
    }
    if (lp.indexOf("uri:") === 0) {
      var uri = p.slice(4);
      try {
        var u = safeUrl.parse(uri, { allowedProtocols: ["https:", "http:"] });
        if ((u.hostname || "").toLowerCase() === dom) return { ok: true, found: found };
      } catch (_e) {
        if (lp.indexOf(dom) !== -1) return { ok: true, found: found };
      }
    }
  }
  return { ok: false, found: found };
}

// _extractBimiCertPolicy - walks the X.509 raw DER to find:
//   - extKeyUsage (id-ce-extKeyUsage 2.5.29.37) - confirms BIMI EKU OID
//   - certificatePolicies (id-ce-certificatePolicies 2.5.29.32) - list
//   - id-pe-logotype (1.3.6.1.5.5.7.1.12) - RFC 3709 SVG payload
function _extractBimiCertPolicy(cert) {
  var rv = { hasMarkVerificationEku: false, policyOids: [], logoSvg: null };
  var rawDer = cert.raw;
  if (!rawDer || rawDer.length === 0) return rv;

  var outer;
  try { outer = asn1.readNode(rawDer, 0); }
  catch (_e) { return rv; }
  if (!outer || !outer.constructed) return rv;
  var topChildren;
  try { topChildren = asn1.readSequence(outer.value); }
  catch (_e) { return rv; }
  if (!topChildren || topChildren.length < 1) return rv;
  var tbs = topChildren[0];
  if (!tbs || !tbs.constructed) return rv;
  var tbsChildren;
  try { tbsChildren = asn1.readSequence(tbs.value); }
  catch (_e) { return rv; }
  // tbsCertificate has extensions [3] EXPLICIT - find the
  // context-specific [3] tag (tagClass=2, tag=3).
  var extsNode = null;
  for (var ti = 0; ti < tbsChildren.length; ti += 1) {
    var n = tbsChildren[ti];
    if (n.tagClass === 2 && n.tag === 3) { extsNode = n; break; }
  }
  if (!extsNode) return rv;
  var seqNode;
  try { seqNode = asn1.readNode(extsNode.value, 0); }
  catch (_e) { return rv; }
  if (!seqNode || !seqNode.constructed) return rv;
  var extList;
  try { extList = asn1.readSequence(seqNode.value); }
  catch (_e) { return rv; }
  for (var ei = 0; ei < extList.length; ei += 1) {
    var ext = extList[ei];
    if (!ext.constructed) continue;
    var extChildren;
    try { extChildren = asn1.readSequence(ext.value); }
    catch (_e) { continue; }
    if (!extChildren || extChildren.length < 2) continue;
    var oid;
    try { oid = asn1.readOid(extChildren[0]); }
    catch (_e) { continue; }
    var octet = extChildren[extChildren.length - 1];
    var inner;
    try { inner = asn1.readNode(octet.value, 0); }
    catch (_e) { continue; }

    if (oid === "2.5.29.37") {
      // ExtendedKeyUsage ::= SEQUENCE OF KeyPurposeId  (KeyPurposeId ::= OBJECT IDENTIFIER)
      if (!inner || !inner.constructed) continue;
      var ekuList;
      try { ekuList = asn1.readSequence(inner.value); }
      catch (_e) { continue; }
      for (var ek = 0; ek < ekuList.length; ek += 1) {
        var ekuOid;
        try { ekuOid = asn1.readOid(ekuList[ek]); }
        catch (_e) { continue; }
        if (ekuOid === BIMI_EKU_MARK_VERIFICATION) rv.hasMarkVerificationEku = true;
      }
    } else if (oid === "2.5.29.32") {
      // certificatePolicies ::= SEQUENCE OF PolicyInformation
      // PolicyInformation ::= SEQUENCE { policyIdentifier OID, ... }
      if (!inner || !inner.constructed) continue;
      var polList;
      try { polList = asn1.readSequence(inner.value); }
      catch (_e) { continue; }
      for (var pi = 0; pi < polList.length; pi += 1) {
        var polItem = polList[pi];
        if (!polItem.constructed) continue;
        var polChildren;
        try { polChildren = asn1.readSequence(polItem.value); }
        catch (_e) { continue; }
        if (polChildren.length === 0) continue;
        try {
          var polOid = asn1.readOid(polChildren[0]);
          if (polOid) rv.policyOids.push(polOid);
        } catch (_e) { /* skip */ }
      }
    } else if (oid === ID_PE_LOGOTYPE) {
      // RFC 3709 4.1 - LogotypeExtn carries SubjectLogo (best-effort
      // SVG extraction; full RFC 3709 unpack requires walking nested
      // SEQUENCEs to LogotypeImageData).
      var found = _scanForEmbeddedSvg(inner, 8); /* allow:raw-byte-literal — string-prefix length for magic-bytes match, not bytes */
      if (found) rv.logoSvg = found;
    }
  }
  return rv;
}

function _scanForEmbeddedSvg(node, depthBudget) {
  if (!node) return null;
  if (depthBudget < 0) return null;

  if (!node.constructed) {
    if (!node.value || node.value.length < 4) return null;
    var prefix = node.value.slice(0, Math.min(node.value.length, 64)).toString("utf8");   /* allow:raw-byte-literal — display truncation length, not bytes */
    if (prefix.indexOf("<svg") !== -1 || /<\?xml[\s\S]*<svg/.test(prefix)) {
      return node.value.toString("utf8");
    }
    return null;
  }

  var children;
  try { children = asn1.readSequence(node.value); }
  catch (_e) {
    try {
      var sub = asn1.readNode(node.value, 0);
      return _scanForEmbeddedSvg(sub, depthBudget - 1);
    } catch (_ee) { return null; }
  }
  for (var i = 0; i < children.length; i += 1) {
    var f = _scanForEmbeddedSvg(children[i], depthBudget - 1);
    if (f) return f;
  }
  return null;
}

function _emitAudit(opts, action, outcome, metadata) {
  var sink = opts && opts.audit;
  try {
    if (sink && typeof sink.safeEmit === "function") {
      sink.safeEmit({ action: action, outcome: outcome, metadata: metadata });
      return;
    }
    var defaultSink = audit();
    if (defaultSink && typeof defaultSink.safeEmit === "function") {
      defaultSink.safeEmit({ action: action, outcome: outcome, metadata: metadata });
    }
  } catch (_e) {
    // drop-silent - by design. Audit failure must not break the
    // BIMI-verify hot path; observability counter takes care of the
    // signal upstream.
  }
}

module.exports = {
  recordShape:                recordShape,
  parseRecord:                parseRecord,
  fetchPolicy:                fetchPolicy,
  fetchAndVerifyMark:         fetchAndVerifyMark,
  validateTinyPsSvg:          validateTinyPsSvg,
  BIMI_VERSION:               BIMI_VERSION,
  BIMI_EKU_MARK_VERIFICATION: BIMI_EKU_MARK_VERIFICATION,
  VMC_POLICY_OID:             VMC_POLICY_OID,
  CMC_POLICY_OID:             CMC_POLICY_OID,
  TINY_PS_MAX_BYTES:          TINY_PS_MAX_BYTES,
  BimiError:                  BimiError,
  MailBimiError:              MailBimiError,
};

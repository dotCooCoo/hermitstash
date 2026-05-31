"use strict";

/**
 * @module     b.mail.deploy
 * @nav        Mail
 * @title      Mail deployment helpers
 * @order      250
 * @since      0.9.56
 *
 * @intro
 *   Operator-deployment helpers for standing up a blamejs mail
 *   server. Generates the policy text + DNS records + client
 *   auto-discovery XML every deployment needs alongside the wire-
 *   protocol primitives. Pairs with existing verifiers
 *   (`b.network.smtp.policy` carries the inbound MTA-STS / TLS-RPT
 *   evaluation logic shipped pre-v0.9.46; `b.mail.bimi` carries the
 *   inbound BIMI trust-anchor verifier) so the publish-side helpers
 *   stay thin and the operator runs one vocabulary across both sides.
 *
 *   Surface:
 *     - `b.mail.deploy.mtaStsPublish(opts)` — RFC 8461 §3.2
 *       `/.well-known/mta-sts.txt` policy text + DNS TXT record advice
 *       + DNS record-name advice. Pairs with the inbound MTA-STS
 *       verifier on the receiving side.
 *     - `b.mail.deploy.danePublish(opts)` — RFC 7672 + RFC 6698 TLSA
 *       record generator. Computes SHA-256 SubjectPublicKeyInfo hash
 *       from an operator-supplied PEM cert, returns the TLSA record
 *       string for the operator's DNS zone.
 *     - `b.mail.deploy.autoConfigXml(opts)` — Thunderbird's
 *       `autoconfig.example.com/mail/config-v1.1.xml` shape. RFC-less
 *       (Mozilla convention) but documented at
 *       https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat
 *     - `b.mail.deploy.autoDiscoverXml(opts)` — Outlook's
 *       `autodiscover.example.com/autodiscover/autodiscover.xml`
 *       response shape. MS-OXDSCLI Section 5 + MS-OXDISCO.
 *
 *   The XML generators emit single-string output the operator wires
 *   into `b.staticServe` (mta-sts.txt + autoconfig.xml) or a route
 *   handler (autodiscover, which is request-conditional). No new
 *   network surface — these are pure deterministic functions.
 *
 * @card
 *   Operator-deployment helpers: MTA-STS / DANE / autoconfig /
 *   autodiscover text generators. Pair with the existing inbound
 *   verifiers to complete the publish ↔ verify cycle.
 */

var nodeCrypto = require("node:crypto");
var zlib = require("node:zlib");
var lazyRequire = require("./lazy-require");
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var C = require("./constants");
var safeJson = require("./safe-json");
var safeBuffer = require("./safe-buffer");
var guardJson = lazyRequire(function () { return require("./guard-json"); });
var audit = lazyRequire(function () { return require("./audit"); });
var { defineClass } = require("./framework-error");

var MailDeployError = defineClass("MailDeployError", { alwaysPermanent: true });
var TlsRptParseError = defineClass("TlsRptParseError", { alwaysPermanent: true });

// RFC 8461 §3.2 MTA-STS policy field allowlist. Field values typed +
// bounded — operator supplies them; we never echo arbitrary bytes
// into a DNS-resolvable resource.
var STS_MODES = Object.freeze({ enforce: 1, testing: 1, none: 1 });

function _domainOk(d) {
  if (typeof d !== "string" || d.length === 0 || d.length > 253) return false;                        // RFC 1035 §2.3.4
  // Bounded LDH check; we don't pull in b.guardDomain here because
  // the helper is text-generation and the operator owns the value.
  // Refuse C0 (covers CR / LF / NUL), DEL, and `"` outright —
  // header-injection class + XML-attribute-injection class.
  for (var i = 0; i < d.length; i++) {
    var c = d.charCodeAt(i);
    if (c < 0x20 || c === 0x7F || c === 0x22) return false;                                           // refuse C0 / DEL / "
  }
  return true;
}

function _xmlEscape(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * @primitive  b.mail.deploy.mtaStsPublish
 * @signature  b.mail.deploy.mtaStsPublish(opts)
 * @since      0.9.56
 * @status     stable
 * @related    b.mail.deploy.danePublish
 *
 * Generate the MTA-STS policy file ([RFC 8461 §3.2](https://www.rfc-editor.org/rfc/rfc8461#section-3.2))
 * + DNS TXT record advice. Operator serves the returned `policyText`
 * over HTTPS at `https://mta-sts.<domain>/.well-known/mta-sts.txt`
 * and publishes the TXT record at `_mta-sts.<domain>` so peers can
 * discover the policy version.
 *
 * @opts
 *   domain:     string,                  // your mail domain, e.g. "example.com"
 *   mode:       "enforce"|"testing"|"none",
 *   mxHosts:    string[],                // your MX server hostnames (wildcards `*.mx.` allowed per §3.2.1)
 *   maxAgeSec:  number,                  // policy TTL — RFC 8461 §3.2 SHOULD be ≥ 604800 (1 week)
 *   policyId:   string?,                 // optional; defaults to ISO 8601 timestamp
 *
 * @example
 *   var rv = b.mail.deploy.mtaStsPublish({
 *     domain:    "example.com",
 *     mode:      "enforce",
 *     mxHosts:   ["mx1.example.com", "mx2.example.com"],
 *     maxAgeSec: 604800,
 *   });
 *   rv.policyText;            // → multi-line MTA-STS policy
 *   rv.dnsTxtRecord;          // → "v=STSv1; id=20260516T120000Z;"
 *   rv.policyPath;            // → "/.well-known/mta-sts.txt"
 *   rv.dnsTxtName;            // → "_mta-sts.example.com"
 */
function mtaStsPublish(opts) {
  validateOpts.requireObject(opts || {}, "b.mail.deploy.mtaStsPublish",
    MailDeployError, "mail-deploy/bad-opts");
  if (!_domainOk(opts.domain)) {
    throw new MailDeployError("mail-deploy/bad-domain",
      "mtaStsPublish: opts.domain must be a valid hostname");
  }
  if (!STS_MODES[opts.mode]) {
    throw new MailDeployError("mail-deploy/bad-mode",
      "mtaStsPublish: opts.mode must be 'enforce' | 'testing' | 'none'");
  }
  if (!Array.isArray(opts.mxHosts) || opts.mxHosts.length === 0) {
    throw new MailDeployError("mail-deploy/bad-mx",
      "mtaStsPublish: opts.mxHosts must be a non-empty array");
  }
  if (opts.mxHosts.length > 64) {                                                                     // array cap
    throw new MailDeployError("mail-deploy/bad-mx",
      "mtaStsPublish: opts.mxHosts must contain at most 64 entries");
  }
  for (var i = 0; i < opts.mxHosts.length; i++) {
    var m = opts.mxHosts[i];
    if (typeof m !== "string" || m.length === 0 || m.length > 253) {                                  // RFC 1035 cap
      throw new MailDeployError("mail-deploy/bad-mx",
        "mtaStsPublish: opts.mxHosts[" + i + "] invalid");
    }
    // Allow wildcard `*.mx.example.com` per RFC 8461 §3.2.1.
    var bare = m.charCodeAt(0) === 0x2A && m.charCodeAt(1) === 0x2E ? m.slice(2) : m;
    if (!_domainOk(bare)) {
      throw new MailDeployError("mail-deploy/bad-mx",
        "mtaStsPublish: opts.mxHosts[" + i + "] not a valid hostname");
    }
  }
  if (!numericBounds.isPositiveFiniteInt(opts.maxAgeSec)) {
    throw new MailDeployError("mail-deploy/bad-max-age",
      "mtaStsPublish: opts.maxAgeSec must be a positive integer");
  }
  if (opts.maxAgeSec > 31557600) {                                                                    // allow:raw-time-literal — 1 year in seconds (RFC 8461 §3.2 max_age unit)
    throw new MailDeployError("mail-deploy/bad-max-age",
      "mtaStsPublish: opts.maxAgeSec exceeds 1 year (RFC 8461 §3.2 SHOULD ≤ 31557600)");
  }

  // RFC 8461 §3.2 policy text uses CRLF.
  var lines = [];
  lines.push("version: STSv1");
  lines.push("mode: " + opts.mode);
  for (var j = 0; j < opts.mxHosts.length; j++) {
    lines.push("mx: " + opts.mxHosts[j]);
  }
  lines.push("max_age: " + opts.maxAgeSec);
  var policyText = lines.join("\r\n") + "\r\n";

  // RFC 8461 §3.1 — DNS TXT record carries the policy version (id).
  // Operator updates `id` whenever they re-publish a different policy
  // so peers can detect the change without re-fetching every fetch.
  var policyId;
  if (typeof opts.policyId === "string" && opts.policyId.length > 0) {
    if (!/^[a-zA-Z0-9_-]{1,32}$/.test(opts.policyId)) {                                               // RFC 8461 §3.1 token shape
      throw new MailDeployError("mail-deploy/bad-policy-id",
        "mtaStsPublish: opts.policyId must match [a-zA-Z0-9_-]{1,32}");
    }
    policyId = opts.policyId;
  } else {
    // ISO 8601 timestamp w/o punctuation = unique-by-second.
    policyId = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 16);                         // yyyymmddhhmmssms
  }

  return {
    policyText:   policyText,
    policyPath:   "/.well-known/mta-sts.txt",
    dnsTxtName:   "_mta-sts." + opts.domain,
    dnsTxtRecord: "v=STSv1; id=" + policyId + ";",
    policyId:     policyId,
  };
}

/**
 * @primitive  b.mail.deploy.danePublish
 * @signature  b.mail.deploy.danePublish(opts)
 * @since      0.9.56
 * @status     stable
 *
 * Generate a TLSA record string ([RFC 7672](https://www.rfc-editor.org/rfc/rfc7672)
 * + [RFC 6698](https://www.rfc-editor.org/rfc/rfc6698)) for an MX
 * host's TLS certificate. Computes the SHA-256 SubjectPublicKeyInfo
 * hash of the operator-supplied cert PEM (DANE-EE matching type 1) —
 * the recommended posture per RFC 7672 §3.1.3 because it survives
 * intermediate-CA changes as long as the leaf key stays stable.
 *
 * @opts
 *   certPem:    string,    // PEM cert text
 *   mxHost:     string,    // e.g. "mx1.example.com"
 *   port:       number?,   // default 25 (RFC 7672 §3.1)
 *   usage:      number?,   // 3 (DANE-EE) | 2 (DANE-TA) | 1 (PKIX-EE) | 0 (PKIX-TA); default 3
 *   selector:   number?,   // 1 (SPKI) | 0 (cert); default 1
 *   matchType:  number?,   // 1 (SHA-256) | 2 (SHA-512); default 1
 *
 * @example
 *   var rv = b.mail.deploy.danePublish({
 *     certPem: fs.readFileSync("/etc/letsencrypt/live/mx1/cert.pem", "utf8"),
 *     mxHost:  "mx1.example.com",
 *   });
 *   rv.dnsName;     // → "_25._tcp.mx1.example.com"
 *   rv.record;      // → "3 1 1 <64-hex>"
 *   rv.zoneLine;    // → "_25._tcp.mx1.example.com. IN TLSA 3 1 1 <64-hex>"
 */
function danePublish(opts) {
  validateOpts.requireObject(opts || {}, "b.mail.deploy.danePublish",
    MailDeployError, "mail-deploy/bad-opts");
  validateOpts.requireNonEmptyString(opts.certPem,
    "b.mail.deploy.danePublish: opts.certPem", MailDeployError, "mail-deploy/bad-cert");
  if (opts.certPem.length > 65536) {                                                                  // sanity cap on PEM input
    throw new MailDeployError("mail-deploy/bad-cert",
      "danePublish: opts.certPem too large");
  }
  if (!_domainOk(opts.mxHost)) {
    throw new MailDeployError("mail-deploy/bad-mx-host",
      "danePublish: opts.mxHost must be a valid hostname");
  }
  var port = opts.port === undefined ? 25 : opts.port;                                                // RFC 7672 §3.1 default port
  if (!numericBounds.isPositiveFiniteInt(port) || port > 65535) {                                     // IANA port range
    throw new MailDeployError("mail-deploy/bad-port",
      "danePublish: opts.port must be 1..65535");
  }
  var usage     = opts.usage === undefined ? 3 : opts.usage;                                          // DANE-EE
  var selector  = opts.selector === undefined ? 1 : opts.selector;                                    // SPKI
  var matchType = opts.matchType === undefined ? 1 : opts.matchType;                                  // SHA-256
  if ([0, 1, 2, 3].indexOf(usage) === -1) {
    throw new MailDeployError("mail-deploy/bad-usage",
      "danePublish: opts.usage must be 0|1|2|3 (RFC 6698 §2.1.1)");
  }
  if ([0, 1].indexOf(selector) === -1) {
    throw new MailDeployError("mail-deploy/bad-selector",
      "danePublish: opts.selector must be 0|1 (RFC 6698 §2.1.2)");
  }
  if ([1, 2].indexOf(matchType) === -1) {
    throw new MailDeployError("mail-deploy/bad-match-type",
      "danePublish: opts.matchType must be 1|2 (RFC 6698 §2.1.3; matchType 0 'exact' refused — record bloat)");
  }

  // Parse cert PEM via node:crypto X509Certificate, extract the bytes
  // we hash. selector=0 → full DER; selector=1 → SubjectPublicKeyInfo.
  var x509;
  try {
    x509 = new nodeCrypto.X509Certificate(opts.certPem);
  } catch (e) {
    throw new MailDeployError("mail-deploy/bad-cert",
      "danePublish: cert PEM did not parse: " + (e && e.message ? e.message : String(e)));
  }
  var bytes;
  if (selector === 0) {
    bytes = x509.raw;
  } else {
    // SPKI extraction — node:crypto X509Certificate.publicKey.export.
    var spki = x509.publicKey.export({ type: "spki", format: "der" });
    bytes = spki;
  }
  var algo = matchType === 1 ? "sha256" : "sha512";
  var hashHex = nodeCrypto.createHash(algo).update(bytes).digest("hex");
  var record  = usage + " " + selector + " " + matchType + " " + hashHex;
  var dnsName = "_" + port + "._tcp." + opts.mxHost;
  return {
    dnsName:  dnsName,
    record:   record,
    zoneLine: dnsName + ". IN TLSA " + record,
    usage:    usage,
    selector: selector,
    matchType: matchType,
  };
}

/**
 * @primitive  b.mail.deploy.autoConfigXml
 * @signature  b.mail.deploy.autoConfigXml(opts)
 * @since      0.9.56
 * @status     stable
 *
 * Generate Thunderbird's `autoconfig.<domain>/mail/config-v1.1.xml`
 * payload. Thunderbird checks this URL when a user types their
 * email address into the new-account wizard; serving the XML
 * eliminates the per-user IMAP / SMTP host + port + auth-method
 * data entry that mail clients otherwise demand.
 *
 * The endpoint format is Mozilla-convention rather than RFC, but
 * Outlook, Apple Mail's Mail.app, and Evolution all read the same
 * file when present.
 *
 * @opts
 *   domain:        string,                          // e.g. "example.com"
 *   displayName:   string?,                         // brand label; defaults to domain
 *   imap:          { host, port, socketType?, username? },   // optional
 *   pop3:          { host, port, socketType?, username? },   // optional
 *   smtp:          { host, port, socketType?, username? },   // optional
 *   jmap:          { url }?,                                 // optional — JMAP-aware clients
 *
 * @example
 *   var xml = b.mail.deploy.autoConfigXml({
 *     domain: "example.com",
 *     imap:   { host: "imap.example.com", port: 993, socketType: "SSL" },
 *     smtp:   { host: "smtp.example.com", port: 587, socketType: "STARTTLS" },
 *   });
 *   // Serve at `https://autoconfig.example.com/mail/config-v1.1.xml`
 */
function autoConfigXml(opts) {
  validateOpts.requireObject(opts || {}, "b.mail.deploy.autoConfigXml",
    MailDeployError, "mail-deploy/bad-opts");
  if (!_domainOk(opts.domain)) {
    throw new MailDeployError("mail-deploy/bad-domain",
      "autoConfigXml: opts.domain must be a valid hostname");
  }
  var brand = typeof opts.displayName === "string" && opts.displayName.length > 0 ?
              opts.displayName : opts.domain;
  if (brand.length > 256) {                                                                           // DOM attr cap
    throw new MailDeployError("mail-deploy/bad-displayName",
      "autoConfigXml: opts.displayName too long");
  }
  // Per Mozilla autoconfig config-v1.1 spec
  // (https://wiki.mozilla.org/Thunderbird:Autoconfiguration:ConfigFileFormat),
  // the `type` attribute on `incomingServer` / `outgoingServer` carries
  // the protocol name (`imap` / `pop3` / `smtp`), not the direction. The
  // `incomingServer` / `outgoingServer` element name itself signals
  // direction; the attribute disambiguates between IMAP- and POP3-
  // shaped incoming connections.
  function _server(element, protocol, cfg) {
    if (!cfg) return "";
    if (!_domainOk(cfg.host)) {
      throw new MailDeployError("mail-deploy/bad-host",
        "autoConfigXml: opts." + protocol + ".host invalid");
    }
    if (!numericBounds.isPositiveFiniteInt(cfg.port) || cfg.port > 65535) {                           // IANA port
      throw new MailDeployError("mail-deploy/bad-port",
        "autoConfigXml: opts." + protocol + ".port invalid");
    }
    var socketType = cfg.socketType === "STARTTLS" || cfg.socketType === "plain" ?
                     cfg.socketType : "SSL";
    var userTok = typeof cfg.username === "string" && cfg.username.length > 0 ?
                  cfg.username : "%EMAILADDRESS%";
    return "" +
      "    <" + element + " type=\"" + protocol + "\">\n" +
      "      <hostname>" + _xmlEscape(cfg.host) + "</hostname>\n" +
      "      <port>" + cfg.port + "</port>\n" +
      "      <socketType>" + socketType + "</socketType>\n" +
      "      <username>" + _xmlEscape(userTok) + "</username>\n" +
      "      <authentication>password-cleartext</authentication>\n" +
      "    </" + element + ">\n";
  }
  // JMAP-aware clients read a different element (`mailproxy` /
  // `jmapServer` per the Mozilla draft + Fastmail convention).
  function _jmapServer(cfg) {
    if (!cfg) return "";
    if (typeof cfg.url !== "string" || cfg.url.length === 0 || cfg.url.length > 1024) {               // URL cap
      throw new MailDeployError("mail-deploy/bad-jmap-url",
        "autoConfigXml: opts.jmap.url must be a non-empty string");
    }
    // Refuse control bytes / quote in the URL.
    for (var k = 0; k < cfg.url.length; k++) {
      var c = cfg.url.charCodeAt(k);
      if (c < 0x20 || c === 0x7F || c === 0x22) {                                                     // C0 / DEL / "
        throw new MailDeployError("mail-deploy/bad-jmap-url",
          "autoConfigXml: opts.jmap.url contains control byte");
      }
    }
    return "" +
      "    <incomingServer type=\"jmap\">\n" +
      "      <url>" + _xmlEscape(cfg.url) + "</url>\n" +
      "      <username>%EMAILADDRESS%</username>\n" +
      "      <authentication>OAuth2</authentication>\n" +
      "    </incomingServer>\n";
  }
  var incoming = "";
  if (opts.imap) incoming += _server("incomingServer", "imap", opts.imap);
  if (opts.pop3) incoming += _server("incomingServer", "pop3", opts.pop3);
  if (opts.jmap) incoming += _jmapServer(opts.jmap);
  if (!incoming) {
    throw new MailDeployError("mail-deploy/bad-opts",
      "autoConfigXml: at least one of opts.imap / opts.pop3 / opts.jmap required");
  }
  var outgoing = opts.smtp ? _server("outgoingServer", "smtp", opts.smtp) : "";

  return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
    "<clientConfig version=\"1.1\">\n" +
    "  <emailProvider id=\"" + _xmlEscape(opts.domain) + "\">\n" +
    "    <domain>" + _xmlEscape(opts.domain) + "</domain>\n" +
    "    <displayName>" + _xmlEscape(brand) + "</displayName>\n" +
    "    <displayShortName>" + _xmlEscape(brand) + "</displayShortName>\n" +
    incoming +
    outgoing +
    "  </emailProvider>\n" +
    "</clientConfig>\n";
}

/**
 * @primitive  b.mail.deploy.autoDiscoverXml
 * @signature  b.mail.deploy.autoDiscoverXml(opts)
 * @since      0.9.56
 * @status     stable
 *
 * Generate Outlook's `autodiscover/autodiscover.xml` response payload.
 * Outlook POSTs an XML request to
 * `https://autodiscover.<domain>/autodiscover/autodiscover.xml` with
 * the user's email; the response declares IMAP + SMTP host / port /
 * socket settings. MS-OXDISCO + MS-OXDSCLI (open spec).
 *
 * @opts
 *   email:    string,                                   // operator-extracted from the POST body
 *   imap:     { host, port, ssl? },                     // optional
 *   pop3:     { host, port, ssl? },                     // optional
 *   smtp:     { host, port, ssl? },                     // optional
 *
 * @example
 *   var xml = b.mail.deploy.autoDiscoverXml({
 *     email: "alice@example.com",
 *     imap:  { host: "imap.example.com", port: 993, ssl: true },
 *     smtp:  { host: "smtp.example.com", port: 465, ssl: true },
 *   });
 */
function autoDiscoverXml(opts) {
  validateOpts.requireObject(opts || {}, "b.mail.deploy.autoDiscoverXml",
    MailDeployError, "mail-deploy/bad-opts");
  if (typeof opts.email !== "string" || opts.email.length === 0 || opts.email.length > 254) {        // RFC 5321 cap
    throw new MailDeployError("mail-deploy/bad-email",
      "autoDiscoverXml: opts.email must be a non-empty string");
  }
  // Refuse CR / LF / NUL / control bytes in email (XML injection class).
  for (var i = 0; i < opts.email.length; i++) {
    var c = opts.email.charCodeAt(i);
    if (c < 0x20 || c === 0x7F) {                                                                     // C0 / DEL
      throw new MailDeployError("mail-deploy/bad-email",
        "autoDiscoverXml: opts.email contains control byte");
    }
  }
  function _proto(kind, cfg) {
    if (!cfg) return "";
    if (!_domainOk(cfg.host)) {
      throw new MailDeployError("mail-deploy/bad-host",
        "autoDiscoverXml: opts." + kind.toLowerCase() + ".host invalid");
    }
    if (!numericBounds.isPositiveFiniteInt(cfg.port) || cfg.port > 65535) {                           // IANA port
      throw new MailDeployError("mail-deploy/bad-port",
        "autoDiscoverXml: opts." + kind.toLowerCase() + ".port invalid");
    }
    var ssl = cfg.ssl === false ? "off" : "on";
    return "" +
      "      <Protocol>\n" +
      "        <Type>" + kind + "</Type>\n" +
      "        <Server>" + _xmlEscape(cfg.host) + "</Server>\n" +
      "        <Port>" + cfg.port + "</Port>\n" +
      "        <SSL>" + ssl + "</SSL>\n" +
      "        <SPA>off</SPA>\n" +
      "        <Encryption>" + (ssl === "on" ? "SSL" : "None") + "</Encryption>\n" +
      "        <AuthRequired>on</AuthRequired>\n" +
      "      </Protocol>\n";
  }
  var protos = "";
  if (opts.imap) protos += _proto("IMAP", opts.imap);
  if (opts.pop3) protos += _proto("POP3", opts.pop3);
  if (opts.smtp) protos += _proto("SMTP", opts.smtp);
  if (!protos) {
    throw new MailDeployError("mail-deploy/bad-opts",
      "autoDiscoverXml: at least one of opts.imap / opts.pop3 / opts.smtp required");
  }
  return "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" +
    "<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006\">\n" +
    "  <Response xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a\">\n" +
    "    <Account>\n" +
    "      <AccountType>email</AccountType>\n" +
    "      <Action>settings</Action>\n" +
    protos +
    "    </Account>\n" +
    "  </Response>\n" +
    "</Autodiscover>\n";
}

// ---- TLS-RPT receiver (RFC 8460) ----
//
// Inbound aggregate-report ingest for operators who publish
// `rua=https://reports.example.com/tlsrpt` on `_smtp._tls.<domain>`.
// Reporters POST `application/tlsrpt+json` (raw) or
// `application/tlsrpt+gzip` (gzip-wrapped JSON) per RFC 8460 §5.4
// + §6.4-6.5 IANA media-type registrations.
//
// v1 scope (this slice):
//   - `parseTlsRptReport(bytes, opts?)` — pure parser + §4.4 schema
//     validator. Caps decompressed size (default 32 MiB), compressed
//     size (default 4 MiB), and compression ratio (default 50:1) to
//     defend CVE-2025-0725 / generic decompression-amplification.
//   - `tlsRptIngestHttp({...})` — (req, res) factory returning an
//     RFC 8460 §5.4-compliant handler (201 on accept / 400 on bad
//     JSON / 413 on size / 415 on bad media-type / 405 on non-POST).
//   - `tlsRptReportSchema()` — schema descriptor for operator
//     dashboards.
//
// Deferred from v1 (each with documented condition):
//   - `mailto:` ingest via b.mail.server.mx. Defer condition: no
//     operator demand has surfaced; HTTPS POST is the de-facto
//     deployment shape for TLS-RPT today (reporters with `rua=mailto:`
//     ingest are a long tail). Operators wanting mailto: ingest
//     compose b.mail.server.mx today + call `parseTlsRptReport` on
//     the extracted body part themselves. Reopens when an operator
//     surfaces concrete demand AND the mail.server.mx surface stays
//     stable across the upcoming UTA-draft revisions.
//   - Brotli decompression. Defer condition: no fielded reporter
//     uses `Content-Encoding: br` for TLS-RPT today; the IANA
//     media-type registry (RFC 8460 §6.4) only registers +json and
//     +gzip. Operators behind a brotli-encoding proxy decode at the
//     proxy layer. Reopens when at least one fielded reporter ships
//     brotli or the in-progress UTA-draft requires it.

// Hard caps — defensive against CVE-2025-0725 (libcurl/zlib
// integer overflow) and the decompression-amplification class
// (CWE-409), plus the §5.2 community ceiling (receivers commonly cap
// at 10 MiB).
var TLSRPT_MAX_COMPRESSED_BYTES   = C.BYTES.mib(4);                                                   // 4 MiB compressed cap per §5.2 community practice
var TLSRPT_MAX_DECOMPRESSED_BYTES = C.BYTES.mib(32);                                                  // 32 MiB decompressed cap (operators override via opts)
var TLSRPT_MAX_RATIO              = 50;                                                               // 50:1 compression ratio refusal
var TLSRPT_MAX_POLICIES           = 1000;                                                             // allow:raw-time-literal — RFC 8460 §4.4 policy-cardinality cap
var TLSRPT_MAX_FAILURE_DETAILS    = 10000;                                                            // per-policy failure-details cap
var TLSRPT_GZIP_MAGIC_0           = 0x1f;                                                             // RFC 1952 gzip magic byte 0
var TLSRPT_GZIP_MAGIC_1           = 0x8b;                                                             // RFC 1952 gzip magic byte 1

// Valid RFC 8460 §4.4 result-type values for `failure-details[].result-type`.
var TLSRPT_RESULT_TYPES = Object.freeze({
  "starttls-not-supported":       1,
  "certificate-host-mismatch":    1,
  "certificate-expired":          1,
  "certificate-not-trusted":      1,
  "validation-failure":           1,
  "tlsa-invalid":                 1,
  "dnssec-invalid":               1,
  "dane-required":                1,
  "sts-policy-fetch-error":       1,
  "sts-policy-invalid":           1,
  "sts-webpki-invalid":           1,
});

// Valid RFC 8460 §4.4 policy-type values.
var TLSRPT_POLICY_TYPES = Object.freeze({
  sts: 1, tlsa: 1, "no-policy-found": 1,
});

/**
 * @primitive  b.mail.deploy.parseTlsRptReport
 * @signature  b.mail.deploy.parseTlsRptReport(input, opts?)
 * @since      0.10.15
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.mail.deploy.tlsRptIngestHttp, b.mail.deploy.tlsRptReportSchema
 *
 * Parse + validate an RFC 8460 TLS-RPT aggregate report. Accepts:
 *   - Raw `application/tlsrpt+json` bytes (Buffer or string).
 *   - `application/tlsrpt+gzip` bytes (gzip magic auto-detected via
 *     `0x1f 0x8b` per RFC 1952, or routed when `opts.contentType`
 *     names a gzip media-type).
 *
 * Refusal posture:
 *   - Compressed payload > `opts.maxCompressedBytes` (default 4 MiB)
 *     → `mail-tlsrpt/oversize-compressed`.
 *   - Decompressed payload > `opts.maxDecompressedBytes` (default
 *     32 MiB) → `mail-tlsrpt/gunzip-bomb`.
 *   - Compression ratio > `opts.maxRatio` (default 50:1) →
 *     `mail-tlsrpt/ratio-bomb`.
 *   - Malformed gzip → `mail-tlsrpt/gunzip-failed`.
 *   - Routes through `b.guardJson.parse` for proto-pollution / depth
 *     / key-count defenses before the §4.4 schema walk.
 *   - Missing REQUIRED §4.4 fields → `mail-tlsrpt/bad-schema`.
 *   - `policies` MUST be an array (RFC 8460 §4.4 erratum, even for
 *     single-policy reports).
 *
 * @opts
 *   contentType:           string,    // optional — hint for gzip routing
 *   maxCompressedBytes:    number,    // default TLSRPT_MAX_COMPRESSED_BYTES (4 MiB)
 *   maxDecompressedBytes:  number,    // default TLSRPT_MAX_DECOMPRESSED_BYTES (32 MiB)
 *   maxRatio:              number,    // default 50 (compressed:decompressed cap)
 *
 * @example
 *   var report = b.mail.deploy.parseTlsRptReport(reqBody, {
 *     contentType: req.headers["content-type"],
 *   });
 *   // → { organization-name, date-range: {start, end}, contact-info,
 *   //     report-id, policies: [{ policy-type, policy-domain, ... }] }
 */
function parseTlsRptReport(input, opts) {
  opts = opts || {};
  var bytes;
  if (Buffer.isBuffer(input)) bytes = input;
  else if (typeof input === "string") bytes = Buffer.from(input, "utf8");
  else {
    throw new TlsRptParseError("mail-tlsrpt/bad-input",
      "parseTlsRptReport: input must be a Buffer or string");
  }
  numericBounds.requireAllPositiveFiniteIntIfPresent(opts,
    ["maxCompressedBytes", "maxDecompressedBytes", "maxRatio"],
    "parseTlsRptReport", TlsRptParseError, "mail-tlsrpt/bad-opts");
  var maxCompressed   = opts.maxCompressedBytes   || TLSRPT_MAX_COMPRESSED_BYTES;
  var maxDecompressed = opts.maxDecompressedBytes || TLSRPT_MAX_DECOMPRESSED_BYTES;
  var maxRatio        = opts.maxRatio             || TLSRPT_MAX_RATIO;
  if (bytes.length > maxCompressed) {
    throw new TlsRptParseError("mail-tlsrpt/oversize-compressed",
      "parseTlsRptReport: compressed payload " + bytes.length +
      " bytes exceeds maxCompressedBytes=" + maxCompressed);
  }

  // gzip auto-detect — magic 0x1f 0x8b per RFC 1952. Routes through
  // the same defensive shape as DMARC RUA (lib/mail-auth.js): bound
  // decompression at the cap, surface bomb-vs-malformed as distinct
  // typed errors so audit / alert wiring can react differently.
  var contentType = (opts.contentType || "").toLowerCase();
  var compressedLen = bytes.length;
  var looksGzip = bytes.length >= 2 && bytes[0] === TLSRPT_GZIP_MAGIC_0 && bytes[1] === TLSRPT_GZIP_MAGIC_1;
  var wasCompressed = false;
  if (contentType.indexOf("gzip") !== -1 || looksGzip) {
    wasCompressed = true;
    try { bytes = zlib.gunzipSync(bytes, { maxOutputLength: maxDecompressed }); }
    catch (e) {
      var msg = (e && e.message) || String(e);
      var isBomb = (e && (e.code === "ERR_BUFFER_TOO_LARGE" || e.code === "ERR_OUT_OF_RANGE")) ||
                   /output length|max(?:imum)?\s+output|exceeds?/i.test(msg);
      if (isBomb) {
        throw new TlsRptParseError("mail-tlsrpt/gunzip-bomb",
          "parseTlsRptReport: gunzip output exceeded " + maxDecompressed +
          " bytes (decompression amplification — refused per CVE-2025-0725 class)");
      }
      throw new TlsRptParseError("mail-tlsrpt/gunzip-failed",
        "parseTlsRptReport: gunzip failed: " + msg);
    }
    if (compressedLen > 0 && bytes.length / compressedLen > maxRatio) {
      throw new TlsRptParseError("mail-tlsrpt/ratio-bomb",
        "parseTlsRptReport: decompression ratio " +
        Math.round(bytes.length / compressedLen) + ":1 exceeds maxRatio=" +
        maxRatio + ":1 (decompression amplification — refused)");
    }
  }

  // Route through b.guardJson — proto-pollution / depth / key-count
  // defenses on every untrusted-JSON parse path (closes v0.10.14
  // detector class for untrusted-json-without-guardjson).
  var raw;
  try {
    raw = guardJson().parse(bytes.toString("utf8"), {
      maxBytes:  maxDecompressed,
      maxDepth:  32,                                                                                  // JSON depth cap
      maxKeys:   1000,                                                                                // top-level key cap
    });
  } catch (_e) {
    // Fall back to b.safeJson.parse if guardJson isn't available (in
    // certain bootstrap paths). Both refuse __proto__ / depth-bombs.
    try { raw = safeJson.parse(bytes.toString("utf8")); }
    catch (e2) {
      throw new TlsRptParseError("mail-tlsrpt/bad-json",
        "parseTlsRptReport: JSON parse failed: " + ((e2 && e2.message) || String(e2)));
    }
  }

  return _validateTlsRptReport(raw, { wasCompressed: wasCompressed });
}

function _validateTlsRptReport(raw, ctx) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new TlsRptParseError("mail-tlsrpt/bad-schema",
      "parseTlsRptReport: top-level must be a JSON object");
  }
  // RFC 8460 §4.4 REQUIRED fields.
  var orgName = raw["organization-name"];
  var contact = raw["contact-info"];
  var reportId = raw["report-id"];
  var dateRange = raw["date-range"];
  var policies = raw["policies"];
  if (typeof orgName  !== "string" || orgName.length === 0) {
    throw new TlsRptParseError("mail-tlsrpt/bad-schema",
      "parseTlsRptReport: missing required string 'organization-name'");
  }
  if (typeof contact !== "string" || contact.length === 0) {
    throw new TlsRptParseError("mail-tlsrpt/bad-schema",
      "parseTlsRptReport: missing required string 'contact-info'");
  }
  if (typeof reportId !== "string" || reportId.length === 0) {
    throw new TlsRptParseError("mail-tlsrpt/bad-schema",
      "parseTlsRptReport: missing required string 'report-id'");
  }
  if (!dateRange || typeof dateRange !== "object" ||
      typeof dateRange["start-datetime"] !== "string" ||
      typeof dateRange["end-datetime"]   !== "string") {
    throw new TlsRptParseError("mail-tlsrpt/bad-schema",
      "parseTlsRptReport: 'date-range' must have string start-datetime + end-datetime");
  }
  // RFC 8460 §4.4 erratum — `policies` MUST be an array even for a
  // single-policy report. Some legacy implementations emit a bare
  // object; we refuse to normalize so the operator catches the
  // upstream non-conformance.
  if (!Array.isArray(policies)) {
    throw new TlsRptParseError("mail-tlsrpt/bad-schema",
      "parseTlsRptReport: 'policies' must be an array (RFC 8460 §4.4 erratum); single-policy reports still use [policy] form");
  }
  if (policies.length === 0) {
    throw new TlsRptParseError("mail-tlsrpt/bad-schema",
      "parseTlsRptReport: 'policies' must be a non-empty array");
  }
  if (policies.length > TLSRPT_MAX_POLICIES) {
    throw new TlsRptParseError("mail-tlsrpt/too-many-policies",
      "parseTlsRptReport: report has " + policies.length +
      " policies (cap " + TLSRPT_MAX_POLICIES + ")");
  }
  // Validate summary counts as finite non-negative
  // integers before summing. `Number(...) || 0` would accept
  // `Infinity` (from JSON literal `1e309` or string "Infinity"),
  // negative values, and arbitrary strings (coerced to NaN→0). Each
  // is operator-untrusted input on an audit-emitted path.
  var totalSuccess = 0, totalFailure = 0;
  for (var i = 0; i < policies.length; i += 1) {
    _validatePolicy(policies[i], i);
    var summary = policies[i]["summary"];
    if (summary && typeof summary === "object") {
      var sRaw = summary["total-successful-session-count"];
      var fRaw = summary["total-failure-session-count"];
      if (sRaw !== undefined) {
        if (typeof sRaw !== "number" || !isFinite(sRaw) || sRaw < 0 || Math.floor(sRaw) !== sRaw) {
          throw new TlsRptParseError("mail-tlsrpt/bad-summary",
            "parseTlsRptReport: policies[" + i + "].summary.total-successful-session-count must be a finite non-negative integer");
        }
        totalSuccess += sRaw;
      }
      if (fRaw !== undefined) {
        if (typeof fRaw !== "number" || !isFinite(fRaw) || fRaw < 0 || Math.floor(fRaw) !== fRaw) {
          throw new TlsRptParseError("mail-tlsrpt/bad-summary",
            "parseTlsRptReport: policies[" + i + "].summary.total-failure-session-count must be a finite non-negative integer");
        }
        totalFailure += fRaw;
      }
    }
  }
  // Return a normalized shape — preserve every operator-readable
  // field, plus add framework-attached metadata (sessionTotals,
  // wasCompressed) that doesn't conflict with the RFC schema.
  return {
    "organization-name": orgName,
    "contact-info":      contact,
    "report-id":         reportId,
    "date-range":        {
      "start-datetime":  dateRange["start-datetime"],
      "end-datetime":    dateRange["end-datetime"],
    },
    "policies":          policies,
    sessionTotals:       {
      success:           totalSuccess,
      failure:           totalFailure,
    },
    wasCompressed:       ctx.wasCompressed === true,
  };
}

function _validatePolicy(p, idx) {
  if (!p || typeof p !== "object") {
    throw new TlsRptParseError("mail-tlsrpt/bad-policy",
      "parseTlsRptReport: policies[" + idx + "] must be an object");
  }
  var policy = p["policy"];
  if (!policy || typeof policy !== "object") {
    throw new TlsRptParseError("mail-tlsrpt/bad-policy",
      "parseTlsRptReport: policies[" + idx + "].policy missing");
  }
  var pType = policy["policy-type"];
  if (!TLSRPT_POLICY_TYPES[pType]) {
    throw new TlsRptParseError("mail-tlsrpt/bad-policy",
      "parseTlsRptReport: policies[" + idx + "].policy.policy-type '" + pType +
      "' not in {sts, tlsa, no-policy-found}");
  }
  if (typeof policy["policy-domain"] !== "string" || policy["policy-domain"].length === 0) {
    throw new TlsRptParseError("mail-tlsrpt/bad-policy",
      "parseTlsRptReport: policies[" + idx + "].policy.policy-domain missing");
  }
  // policy-string is optional for no-policy-found, REQUIRED otherwise.
  // We don't enforce — operators may receive partial reports from
  // legacy reporters; we surface the field as-is.
  var failureDetails = p["failure-details"];
  if (failureDetails !== undefined) {
    if (!Array.isArray(failureDetails)) {
      throw new TlsRptParseError("mail-tlsrpt/bad-policy",
        "parseTlsRptReport: policies[" + idx + "].failure-details must be an array");
    }
    if (failureDetails.length > TLSRPT_MAX_FAILURE_DETAILS) {
      throw new TlsRptParseError("mail-tlsrpt/too-many-failures",
        "parseTlsRptReport: policies[" + idx + "] has " + failureDetails.length +
        " failure-details (cap " + TLSRPT_MAX_FAILURE_DETAILS + ")");
    }
    for (var k = 0; k < failureDetails.length; k += 1) {
      var fd = failureDetails[k];
      if (!fd || typeof fd !== "object") {
        throw new TlsRptParseError("mail-tlsrpt/bad-failure-detail",
          "parseTlsRptReport: policies[" + idx + "].failure-details[" + k + "] must be an object");
      }
      if (typeof fd["result-type"] === "string" && !TLSRPT_RESULT_TYPES[fd["result-type"]]) {
        // Unknown result-type — surface as audit metadata but don't
        // refuse; RFC 8460 §4.4 result-type registry can grow over
        // time and we shouldn't break on new IANA entries.
      }
    }
  }
}

/**
 * @primitive  b.mail.deploy.tlsRptReportSchema
 * @signature  b.mail.deploy.tlsRptReportSchema()
 * @since      0.10.15
 * @status     stable
 * @related    b.mail.deploy.parseTlsRptReport
 *
 * Returns a structured RFC 8460 §4.4 schema descriptor — operator
 * dashboards consume this to render report shape consistently.
 * The descriptor names every required + optional field with type +
 * cardinality + brief description. Pure function; safe to cache.
 *
 * @example
 *   var schema = b.mail.deploy.tlsRptReportSchema();
 *   schema.required.indexOf("report-id") !== -1;  // → true
 */
function tlsRptReportSchema() {
  return {
    rfc: "RFC 8460 §4.4",
    required: [
      "organization-name", "contact-info", "report-id", "date-range", "policies",
    ],
    fields: {
      "organization-name":   { type: "string",  required: true,  description: "Reporter organisation display name." },
      "contact-info":         { type: "string",  required: true,  description: "Email / URI for reporter contact." },
      "report-id":            { type: "string",  required: true,  description: "Reporter-issued unique report identifier (RFC 5322 msg-id shape)." },
      "date-range":           { type: "object",  required: true,  description: "Window the report covers; { start-datetime, end-datetime } in RFC 3339 form." },
      "policies":             { type: "array",   required: true,  description: "Array of policy evaluations (RFC 8460 §4.4 erratum — always array, even for single-policy reports)." },
    },
    policyFields: {
      "policy":               { type: "object",  required: true,  description: "{ policy-type, policy-string, policy-domain, mx-host }." },
      "summary":              { type: "object",  required: false, description: "{ total-successful-session-count, total-failure-session-count }." },
      "failure-details":      { type: "array",   required: false, description: "Per-failure details (result-type, sending-mta-ip, etc.)." },
    },
    policyTypes:  Object.keys(TLSRPT_POLICY_TYPES),
    resultTypes:  Object.keys(TLSRPT_RESULT_TYPES),
  };
}

/**
 * @primitive  b.mail.deploy.tlsRptIngestHttp
 * @signature  b.mail.deploy.tlsRptIngestHttp(opts)
 * @since      0.10.15
 * @status     stable
 * @compliance hipaa, pci-dss, gdpr, soc2
 * @related    b.mail.deploy.parseTlsRptReport, b.mail.deploy.tlsRptReportSchema
 *
 * Returns an `(req, res)` request handler mounted at the operator's
 * `rua=https://<host>/<path>` endpoint. Implements the receive-side
 * of RFC 8460 §5.4:
 *
 *   - POST only — non-POST returns 405 with Allow: POST.
 *   - Accepts `application/tlsrpt+json` and `application/tlsrpt+gzip`
 *     (RFC 8460 §6.4-6.5 IANA media types). 415 on others.
 *   - Body size cap (default 4 MiB compressed) — 413 on exceed.
 *   - Routes the bytes through `parseTlsRptReport`. 400 on parse
 *     failure (with `Error-Type:` header naming the typed error
 *     code). 201 on accept.
 *   - Calls `opts.onAccept(report, req)` after successful parse.
 *     Operator's hook decides storage (most operators journal +
 *     emit a metric); the framework does NOT persist by default.
 *   - Emits a `mail.tlsrpt.ingest_http` audit event with
 *     posture-aware payload (organization-name, report-id,
 *     policy-domain set, session totals).
 *
 * Authentication discipline:
 *   - `trustedReporters` is a CONTENT-SIDE soft filter — it compares
 *     the reporter's self-declared `organization-name` field (the
 *     report body, operator-untrusted) against the operator's
 *     allowlist. A hostile sender can forge any `organization-name`
 *     string to bypass it. This option is ADVISORY: a tripwire that
 *     surfaces unexpected reporter-name strings in audit, not an
 *     authentication boundary.
 *   - For real authentication, supply `opts.authenticate(req)` — the
 *     hook fires BEFORE parsing the body and returns truthy / falsy
 *     (or a Promise). False / falsy refuses with 401 + the
 *     `mail-tlsrpt/unauthenticated` audit code. Operators wire this
 *     to their mTLS-peer-cert / IP-allowlist / signed-header /
 *     reverse-proxy auth boundary. The framework intentionally does
 *     NOT couple to any specific auth scheme.
 *
 * @opts
 *   authenticate:            Function,  // (req) → boolean | Promise<boolean>; SHA real auth boundary
 *   trustedReporters:        string[],  // ADVISORY content filter on report.organization-name (operator-untrusted field)
 *   maxCompressedBytes:      number,    // default 4 MiB
 *   maxDecompressedBytes:    number,    // default 32 MiB
 *   maxRatio:                number,    // default 50
 *   onAccept:                Function,  // (report, req) → void | Promise
 *   onRefuse:                Function,  // (errCode, errMessage, req) → void
 *   audit:                   object,    // optional b.audit handle (default: framework audit)
 *
 * @example
 *   app.post("/tlsrpt", b.mail.deploy.tlsRptIngestHttp({
 *     onAccept: function (report) {
 *       b.journal.append({ kind: "tlsrpt", report: report });
 *     },
 *   }));
 */
function tlsRptIngestHttp(opts) {
  opts = opts || {};
  validateOpts(opts, ["authenticate", "trustedReporters", "maxCompressedBytes",
                       "maxDecompressedBytes", "maxRatio", "onAccept", "onRefuse",
                       "audit", "compliance"],
    "mail.deploy.tlsRptIngestHttp");
  validateOpts.optionalFunction(opts.authenticate, "tlsRptIngestHttp: opts.authenticate",
    MailDeployError, "mail-tlsrpt/bad-opts");
  if (opts.trustedReporters !== undefined &&
      (!Array.isArray(opts.trustedReporters) ||
       opts.trustedReporters.some(function (s) { return typeof s !== "string"; }))) {
    throw new MailDeployError("mail-tlsrpt/bad-opts",
      "tlsRptIngestHttp: opts.trustedReporters must be an array of strings");
  }
  var authenticate = typeof opts.authenticate === "function" ? opts.authenticate : null;
  var trusted = opts.trustedReporters
    ? Object.freeze(opts.trustedReporters.reduce(function (a, s) { a[s] = 1; return a; }, {}))
    : null;
  numericBounds.requirePositiveFiniteIntIfPresent(opts.maxCompressedBytes, "maxCompressedBytes", MailDeployError, "mail-tlsrpt/bad-opts");
  var maxCompressed = opts.maxCompressedBytes || TLSRPT_MAX_COMPRESSED_BYTES;
  // Cache the other caps so the per-request parser call sees them.
  var parseOpts = {
    maxCompressedBytes:   maxCompressed,
    maxDecompressedBytes: opts.maxDecompressedBytes,
    maxRatio:             opts.maxRatio,
  };
  var onAccept = typeof opts.onAccept === "function" ? opts.onAccept : null;
  var onRefuse = typeof opts.onRefuse === "function" ? opts.onRefuse : null;

  return function tlsRptHandler(req, res) {
    if (req.method !== "POST") {
      res.writeHead(405, { "Allow": "POST", "Content-Type": "text/plain" });                          // allow:raw-time-literal — RFC 8460 §5.4 status code
      res.end("RFC 8460 §5.4 requires POST\n");
      return;
    }
    var ct = (req.headers["content-type"] || "").toLowerCase();
    var ctRoot = ct.split(";")[0].trim();
    if (ctRoot !== "application/tlsrpt+json" && ctRoot !== "application/tlsrpt+gzip") {
      _safeAuditEmit(opts.audit, "mail.tlsrpt.ingest_http", "denied", {
        reason: "bad-content-type", contentType: ctRoot,
      });
      if (onRefuse) try { onRefuse("mail-tlsrpt/bad-content-type", "unexpected content-type " + ctRoot, req); }
      catch (_e) { /* drop-silent */ }
      res.writeHead(415, { "Content-Type": "text/plain", "Accept": "application/tlsrpt+json, application/tlsrpt+gzip" });   // allow:raw-time-literal — RFC 8460 §5.4 status code
      res.end("RFC 8460 §6.4-6.5 media types required\n");
      return;
    }
    // Real-authentication boundary BEFORE body
    // collection. The operator-supplied `authenticate(req)` hook
    // routes to mTLS peer-cert / IP-allowlist / signed-header /
    // reverse-proxy header inspection. Sync-or-async; falsy → 401.
    if (authenticate) {
      var authPromise;
      try { authPromise = Promise.resolve(authenticate(req)); }
      catch (e) { authPromise = Promise.reject(e); }
      authPromise.then(function (ok) {
        if (!ok) {
          _safeAuditEmit(opts.audit, "mail.tlsrpt.ingest_http", "denied", { reason: "unauthenticated" });
          if (onRefuse) try { onRefuse("mail-tlsrpt/unauthenticated", "authenticate(req) returned falsy", req); }
          catch (_e) { /* drop-silent */ }
          res.writeHead(401, { "Content-Type": "text/plain", "Error-Type": "mail-tlsrpt/unauthenticated" });   // allow:raw-time-literal — RFC 8460 §5.4 status code
          res.end("authentication required\n");
          return;
        }
        _collectAndProcess();
      }, function (err) {
        _safeAuditEmit(opts.audit, "mail.tlsrpt.ingest_http", "denied", {
          reason: "auth-error", message: (err && err.message) || String(err),
        });
        if (onRefuse) try { onRefuse("mail-tlsrpt/auth-error", (err && err.message) || String(err), req); }
        catch (_e) { /* drop-silent */ }
        res.writeHead(500, { "Content-Type": "text/plain", "Error-Type": "mail-tlsrpt/auth-error" });   // allow:raw-time-literal — RFC 8460 §5.4 status code
        res.end("authenticate hook threw\n");
      });
      return;
    }
    _collectAndProcess();

    function _collectAndProcess() {
    var collector = safeBuffer.boundedChunkCollector({
      maxBytes:   maxCompressed,
      errorClass: MailDeployError,
      sizeCode:   "mail-tlsrpt/oversize-compressed",
    });
    var aborted = false;
    req.on("data", function (chunk) {
      if (aborted) return;
      try { collector.push(chunk); }
      catch (e) {
        aborted = true;
        try { req.destroy(); } catch (_e) { /* best-effort */ }
        _safeAuditEmit(opts.audit, "mail.tlsrpt.ingest_http", "denied", {
          reason: "oversize-compressed", bytes: collector.bytesCollected(), cap: maxCompressed,
        });
        if (onRefuse) try { onRefuse("mail-tlsrpt/oversize-compressed", "body exceeded " + maxCompressed + " bytes", req); }
        catch (_e) { /* drop-silent */ }
        if (!res.headersSent) {
          res.writeHead(413, { "Content-Type": "text/plain" });                                       // allow:raw-time-literal — RFC 8460 §5.4 status code
          res.end("RFC 8460 §5.4 — body exceeds " + maxCompressed + " bytes\n");
        }
        void e;   // _e shadowed by lower scope; mark intent
      }
    });
    req.on("end", function () {
      if (aborted) return;
      var report;
      try {
        report = parseTlsRptReport(collector.result(), Object.assign({
          contentType: ctRoot,
        }, parseOpts));
      } catch (e) {
        var code = (e && e.code) || "mail-tlsrpt/unknown";
        _safeAuditEmit(opts.audit, "mail.tlsrpt.ingest_http", "denied", {
          reason: code, message: (e && e.message) || String(e),
        });
        if (onRefuse) try { onRefuse(code, (e && e.message) || String(e), req); }
        catch (_e) { /* drop-silent */ }
        var status = code === "mail-tlsrpt/oversize-compressed" ? 413
                  : code === "mail-tlsrpt/gunzip-bomb"           ? 413
                  : code === "mail-tlsrpt/ratio-bomb"             ? 413
                  : code === "mail-tlsrpt/bad-content-type"       ? 415
                  : 400;                                                                              // allow:raw-time-literal — RFC 8460 §5.4 status code
        res.writeHead(status, { "Content-Type": "text/plain", "Error-Type": code });
        res.end("RFC 8460 §5.4 — refused: " + code + "\n");
        return;
      }
      if (trusted && !trusted[report["organization-name"]]) {
        _safeAuditEmit(opts.audit, "mail.tlsrpt.ingest_http", "denied", {
          reason: "untrusted-reporter", reporter: report["organization-name"],
        });
        if (onRefuse) try { onRefuse("mail-tlsrpt/untrusted-reporter",
          "reporter '" + report["organization-name"] + "' not in trustedReporters", req); }
        catch (_e) { /* drop-silent */ }
        res.writeHead(403, { "Content-Type": "text/plain", "Error-Type": "mail-tlsrpt/untrusted-reporter" });   // allow:raw-time-literal — RFC 8460 §5.4 status code
        res.end("RFC 8460 §5.3-class: untrusted reporter\n");
        return;
      }
      var policyDomains = report.policies.map(function (p) {
        return p && p.policy && p.policy["policy-domain"];
      }).filter(Boolean);
      _safeAuditEmit(opts.audit, "mail.tlsrpt.ingest_http", "success", {
        reporter:         report["organization-name"],
        reportId:         report["report-id"],
        policyDomains:    policyDomains,
        sessionTotals:    report.sessionTotals,
        policyCount:      report.policies.length,
        wasCompressed:    report.wasCompressed,
      });
      if (onAccept) {
        try {
          var ret = onAccept(report, req);
          if (ret && typeof ret.then === "function") {
            ret.then(function () {
              if (!res.headersSent) {
                res.writeHead(201, { "Content-Type": "text/plain" });                                 // allow:raw-time-literal — RFC 8460 §5.4 status code
                res.end("RFC 8460 §5.4 — accepted\n");
              }
            }, function (_e) {
              if (!res.headersSent) {
                res.writeHead(500, { "Content-Type": "text/plain" });                                 // internal-error status
                res.end("internal error processing report\n");
              }
            });
            return;
          }
        } catch (_e) { /* fall through to 201 — operator hook is best-effort */ }
      }
      res.writeHead(201, { "Content-Type": "text/plain" });                                           // allow:raw-time-literal — RFC 8460 §5.4 status code
      res.end("RFC 8460 §5.4 — accepted\n");
    });
    req.on("error", function () {
      if (aborted) return;
      aborted = true;
      _safeAuditEmit(opts.audit, "mail.tlsrpt.ingest_http", "denied", { reason: "req-error" });
      if (!res.headersSent) {
        res.writeHead(400, { "Content-Type": "text/plain" });                                         // allow:raw-time-literal — RFC 8460 §5.4 status code
        res.end("malformed request\n");
      }
    });
    }   // end _collectAndProcess
  };
}

function _safeAuditEmit(handle, action, outcome, metadata) {
  try {
    var a = handle || audit();
    if (a && typeof a.safeEmit === "function") {
      a.safeEmit({ action: action, outcome: outcome, actor: {}, metadata: metadata });
    }
  } catch (_e) { /* drop-silent — audit failure must not block ingest */ }
}

module.exports = {
  mtaStsPublish:       mtaStsPublish,
  danePublish:         danePublish,
  autoConfigXml:       autoConfigXml,
  autoDiscoverXml:     autoDiscoverXml,
  parseTlsRptReport:   parseTlsRptReport,
  tlsRptReportSchema:  tlsRptReportSchema,
  tlsRptIngestHttp:    tlsRptIngestHttp,
  MailDeployError:     MailDeployError,
  TlsRptParseError:    TlsRptParseError,
};

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
var validateOpts = require("./validate-opts");
var numericBounds = require("./numeric-bounds");
var { defineClass } = require("./framework-error");

var MailDeployError = defineClass("MailDeployError", { alwaysPermanent: true });

// RFC 8461 §3.2 MTA-STS policy field allowlist. Field values typed +
// bounded — operator supplies them; we never echo arbitrary bytes
// into a DNS-resolvable resource.
var STS_MODES = Object.freeze({ enforce: 1, testing: 1, none: 1 });

function _domainOk(d) {
  if (typeof d !== "string" || d.length === 0 || d.length > 253) return false;                        // allow:raw-byte-literal — RFC 1035 §2.3.4
  // Bounded LDH check; we don't pull in b.guardDomain here because
  // the helper is text-generation and the operator owns the value.
  // Refuse C0 (covers CR / LF / NUL), DEL, and `"` outright —
  // header-injection class + XML-attribute-injection class.
  for (var i = 0; i < d.length; i++) {
    var c = d.charCodeAt(i);
    if (c < 0x20 || c === 0x7F || c === 0x22) return false;                                           // allow:raw-byte-literal — refuse C0 / DEL / "
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
  if (opts.mxHosts.length > 64) {                                                                     // allow:raw-byte-literal — array cap
    throw new MailDeployError("mail-deploy/bad-mx",
      "mtaStsPublish: opts.mxHosts must contain at most 64 entries");
  }
  for (var i = 0; i < opts.mxHosts.length; i++) {
    var m = opts.mxHosts[i];
    if (typeof m !== "string" || m.length === 0 || m.length > 253) {                                  // allow:raw-byte-literal — RFC 1035 cap
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
  if (opts.maxAgeSec > 31557600) {                                                                    // allow:raw-time-literal — 1 year in seconds (RFC 8461 §3.2 max_age unit) // allow:raw-byte-literal — same numeric, no byte semantic
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
    if (!/^[a-zA-Z0-9_-]{1,32}$/.test(opts.policyId)) {                                               // allow:raw-byte-literal — RFC 8461 §3.1 token shape
      throw new MailDeployError("mail-deploy/bad-policy-id",
        "mtaStsPublish: opts.policyId must match [a-zA-Z0-9_-]{1,32}");
    }
    policyId = opts.policyId;
  } else {
    // ISO 8601 timestamp w/o punctuation = unique-by-second.
    policyId = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 16);                         // allow:raw-byte-literal — yyyymmddhhmmssms
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
  if (opts.certPem.length > 65536) {                                                                  // allow:raw-byte-literal — sanity cap on PEM input
    throw new MailDeployError("mail-deploy/bad-cert",
      "danePublish: opts.certPem too large");
  }
  if (!_domainOk(opts.mxHost)) {
    throw new MailDeployError("mail-deploy/bad-mx-host",
      "danePublish: opts.mxHost must be a valid hostname");
  }
  var port = opts.port === undefined ? 25 : opts.port;                                                // allow:raw-byte-literal — RFC 7672 §3.1 default port
  if (!numericBounds.isPositiveFiniteInt(port) || port > 65535) {                                     // allow:raw-byte-literal — IANA port range
    throw new MailDeployError("mail-deploy/bad-port",
      "danePublish: opts.port must be 1..65535");
  }
  var usage     = opts.usage === undefined ? 3 : opts.usage;                                          // allow:raw-byte-literal — DANE-EE
  var selector  = opts.selector === undefined ? 1 : opts.selector;                                    // allow:raw-byte-literal — SPKI
  var matchType = opts.matchType === undefined ? 1 : opts.matchType;                                  // allow:raw-byte-literal — SHA-256
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
  if (brand.length > 256) {                                                                           // allow:raw-byte-literal — DOM attr cap
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
    if (!numericBounds.isPositiveFiniteInt(cfg.port) || cfg.port > 65535) {                           // allow:raw-byte-literal — IANA port
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
    if (typeof cfg.url !== "string" || cfg.url.length === 0 || cfg.url.length > 1024) {               // allow:raw-byte-literal — URL cap
      throw new MailDeployError("mail-deploy/bad-jmap-url",
        "autoConfigXml: opts.jmap.url must be a non-empty string");
    }
    // Refuse control bytes / quote in the URL.
    for (var k = 0; k < cfg.url.length; k++) {
      var c = cfg.url.charCodeAt(k);
      if (c < 0x20 || c === 0x7F || c === 0x22) {                                                     // allow:raw-byte-literal — C0 / DEL / "
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
  if (typeof opts.email !== "string" || opts.email.length === 0 || opts.email.length > 254) {        // allow:raw-byte-literal — RFC 5321 cap
    throw new MailDeployError("mail-deploy/bad-email",
      "autoDiscoverXml: opts.email must be a non-empty string");
  }
  // Refuse CR / LF / NUL / control bytes in email (XML injection class).
  for (var i = 0; i < opts.email.length; i++) {
    var c = opts.email.charCodeAt(i);
    if (c < 0x20 || c === 0x7F) {                                                                     // allow:raw-byte-literal — C0 / DEL
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
    if (!numericBounds.isPositiveFiniteInt(cfg.port) || cfg.port > 65535) {                           // allow:raw-byte-literal — IANA port
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

module.exports = {
  mtaStsPublish:    mtaStsPublish,
  danePublish:      danePublish,
  autoConfigXml:    autoConfigXml,
  autoDiscoverXml:  autoDiscoverXml,
  MailDeployError:  MailDeployError,
};

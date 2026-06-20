"use strict";

var dns = require("node:dns");
var net = require("node:net");
var https = require("node:https");
var nodeTls = require("node:tls");
var dnsPromises = dns.promises;

var C = require("./constants");
var bCrypto = require("./crypto");
var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");
var { boundedMap } = require("./bounded-map");

var DnsError = defineClass("DnsError", { alwaysPermanent: false });

// Protocol-fixed byte counts and radixes — passthrough through C.BYTES
// keeps every numeric literal routed through one helper.
var DNS_QTYPE_AAAA   = 28;                  // RFC 3596 — IPv6 record type
var IPV6_ADDR_BYTES  = C.BYTES.bytes(16);   // IPv6 address octet length
var IPV6_HEX_GROUPS  = C.BYTES.bytes(8);    // IPv6 16-bit hex groups
var HEX_RADIX        = C.BYTES.bytes(16);   // parseInt / toString radix-16

var observability = lazyRequire(function () { return require("./observability"); });
var safeEnv = require("./parsers/safe-env");

var STATE = {
  servers:        null,
  resultOrder:    null,
  family:         0,
  lookupTimeoutMs: 0,
  cacheTtlMs:     0,
  cacheNegativeTtlMs: 0,
  doh:            null,
  dot:            null,
  // Default-on secure DNS (DoH via Cloudflare) when neither doh nor dot
  // is operator-configured AND no opt-out env var is set. Operators
  // who explicitly want the system resolver call useSystemResolver()
  // or set BLAMEJS_DNS_TRANSPORT=system. Default-on (security defaults are not opt-in).
  systemResolver: false,
};

// Default DoH provider when nothing is configured. Cloudflare's
// 1.1.1.1 service is privacy-respecting, free, and global.
var DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query";

// RFC 6761 + RFC 6762 + operator-internal special-form host names that
// public DoH/DoT providers don't resolve. Local lookups for these names
// route through node:dns which honours /etc/hosts + LDH locally.
var LOCAL_SUFFIXES = [".localhost", ".local", ".test", ".invalid",
                      ".internal", ".intranet", ".lan", ".home", ".corp"];
function _isLocalFormHost(host) {
  if (typeof host !== "string" || host.length === 0) return true;
  // Strip the trailing root-zone dot BEFORE any reserved-name compare.
  // RFC 1034 §3.1 — `foo.` is the absolute form of `foo` (both resolve
  // to the same target). Without the strip, `localhost.` would slip
  // past the reserved-form check and reach a public DoH/DoT provider
  // that maps it to NXDOMAIN, which downstream consumers might then
  // try to resolve via system fallback.
  while (host.length > 0 && host.charAt(host.length - 1) === ".") {
    host = host.slice(0, -1);
  }
  if (host === "localhost") return true;
  // IP literal — skip DNS resolution entirely (caller passes through).
  if (net.isIP(host)) return true;
  var lc = host.toLowerCase();
  for (var i = 0; i < LOCAL_SUFFIXES.length; i += 1) {
    if (lc.length > LOCAL_SUFFIXES[i].length &&
        lc.slice(-LOCAL_SUFFIXES[i].length) === LOCAL_SUFFIXES[i]) {
      return true;
    }
  }
  return false;
}

function _ensureSecureDefault() {
  if (STATE.doh || STATE.dot || STATE.systemResolver) return;
  var override = safeEnv.readVar("BLAMEJS_DNS_TRANSPORT");
  if (override === "system") { STATE.systemResolver = true; return; }
  if (override === "dot") {
    // Cloudflare 1.1.1.1 over TLS, port 853.
    STATE.dot = { host: "1.1.1.1", port: 853, servername: "1.1.1.1", ca: null };  // IANA-assigned DoT port
    return;
  }
  // Default: DoH via Cloudflare.
  STATE.doh = { url: DEFAULT_DOH_URL, method: null, ca: null };
}

// Resolver caches are keyed on (hostname, family). Hostnames reaching the
// resolver are request-influenced (outbound HTTP targets, mail MX lookups,
// operator-supplied URLs), and expired entries are only reclaimed lazily on
// a re-query of the SAME key — so a stream of unique hostnames would grow
// these without bound. Cap them; evict-oldest is free (DNS re-resolves on
// the next miss). The cap bounds peak memory even with no periodic sweep.
var DNS_CACHE_MAX_ENTRIES = 4096;
var POSITIVE_CACHE = boundedMap({ maxEntries: DNS_CACHE_MAX_ENTRIES, policy: "evict-oldest" });
var NEGATIVE_CACHE = boundedMap({ maxEntries: DNS_CACHE_MAX_ENTRIES, policy: "evict-oldest" });

function _now() { return Date.now(); }

function _cacheGet(host, family) {
  var key = host + "/" + family;
  var pos = POSITIVE_CACHE.get(key);
  if (pos && pos.expiresAt > _now()) return { hit: true, value: pos.value };
  if (pos) POSITIVE_CACHE.delete(key);
  var neg = NEGATIVE_CACHE.get(key);
  if (neg && neg.expiresAt > _now()) return { hit: true, error: neg.error };
  if (neg) NEGATIVE_CACHE.delete(key);
  return { hit: false };
}

function _cachePutPositive(host, family, value) {
  if (STATE.cacheTtlMs <= 0) return;
  POSITIVE_CACHE.set(host + "/" + family, {
    value:     value,
    expiresAt: _now() + STATE.cacheTtlMs,
  });
}

function _cachePutNegative(host, family, error) {
  if (STATE.cacheTtlMs <= 0) return;
  var ttl = STATE.cacheNegativeTtlMs > 0 ? STATE.cacheNegativeTtlMs : Math.min(STATE.cacheTtlMs, C.TIME.seconds(30));
  NEGATIVE_CACHE.set(host + "/" + family, {
    error:     error,
    expiresAt: _now() + ttl,
  });
}

function _clearCache() {
  POSITIVE_CACHE.clear();
  NEGATIVE_CACHE.clear();
}

function setServers(serverList) {
  if (!Array.isArray(serverList) || serverList.length === 0) {
    throw new DnsError("dns/bad-servers", "dns.setServers: expected non-empty array of resolver IPs");
  }
  for (var i = 0; i < serverList.length; i++) {
    var s = serverList[i];
    if (typeof s !== "string" || s.length === 0) {
      throw new DnsError("dns/bad-server", "dns.setServers[" + i + "]: expected non-empty string, got " + typeof s);
    }
  }
  STATE.servers = serverList.slice();
  try { dns.setServers(serverList); } catch (e) {
    throw new DnsError("dns/setservers-failed", "dns.setServers failed: " + e.message);
  }
  _clearCache();
  observability().safeEvent("network.dns.servers.set", 1, { count: serverList.length });
}

function getServers() {
  if (STATE.servers) return STATE.servers.slice();
  try { return dns.getServers(); } catch (_e) { return []; }
}

function setResultOrder(order) {
  if (order !== "ipv4first" && order !== "verbatim" && order !== "ipv6first") {
    throw new DnsError("dns/bad-result-order",
      "dns.setResultOrder: expected 'ipv4first' | 'verbatim' | 'ipv6first', got " + JSON.stringify(order));
  }
  STATE.resultOrder = order;
  if (order === "ipv6first") {
    try { dns.setDefaultResultOrder("verbatim"); } catch (_e) { /* node may not support setter on this version — best-effort */ }
  } else {
    try { dns.setDefaultResultOrder(order); } catch (_e) { /* node may not support setter on this version — best-effort */ }
  }
  _clearCache();
  observability().safeEvent("network.dns.result_order.set", 1, { order: order });
}

function setFamily(fam) {
  if (fam !== 0 && fam !== 4 && fam !== 6) {
    throw new DnsError("dns/bad-family", "dns.setFamily: expected 0 | 4 | 6, got " + JSON.stringify(fam));
  }
  STATE.family = fam;
  _clearCache();
}

function setLookupTimeoutMs(ms) {
  if (typeof ms !== "number" || !isFinite(ms) || ms < 0) {
    throw new DnsError("dns/bad-timeout",
      "dns.setLookupTimeoutMs: expected non-negative finite number, got " + JSON.stringify(ms));
  }
  STATE.lookupTimeoutMs = ms;
}

function setCacheTtlMs(ms, negativeMs) {
  if (typeof ms !== "number" || !isFinite(ms) || ms < 0) {
    throw new DnsError("dns/bad-cache-ttl",
      "dns.setCacheTtlMs: expected non-negative finite number, got " + JSON.stringify(ms));
  }
  STATE.cacheTtlMs = ms;
  if (negativeMs !== undefined) {
    if (typeof negativeMs !== "number" || !isFinite(negativeMs) || negativeMs < 0) {
      throw new DnsError("dns/bad-cache-ttl",
        "dns.setCacheTtlMs negativeMs: expected non-negative finite number, got " + JSON.stringify(negativeMs));
    }
    STATE.cacheNegativeTtlMs = negativeMs;
  }
  if (ms === 0) _clearCache();
}

// Operator opt-out from the default-on secure DNS. After calling this,
// every lookup routes through node:dns (the OS resolver). Equivalent
// to setting BLAMEJS_DNS_TRANSPORT=system. Operators on internal-DNS
// deployments (split-horizon, custom resolver appliances) need this
// to keep their hostnames resolving locally.
function useSystemResolver() {
  STATE.doh = null;
  STATE.dot = null;
  STATE.systemResolver = true;
  _resetDotPool();
  _clearCache();
  observability().safeEvent("network.dns.system_resolver.set", 1, {});
}

function useDnsOverHttps(opts) {
  opts = opts || {};
  validateOpts(opts, ["provider", "url", "method", "ca"], "dns.useDnsOverHttps");
  var url = opts.url;
  if (!url && opts.provider) {
    var p = String(opts.provider).toLowerCase();
    if (p === "cloudflare") url = "https://cloudflare-dns.com/dns-query";
    else if (p === "google")  url = "https://dns.google/dns-query";
    else if (p === "quad9")   url = "https://dns.quad9.net/dns-query";
    else throw new DnsError("dns/bad-doh-provider", "dns.useDnsOverHttps: unknown provider '" + opts.provider + "'");
  }
  if (typeof url !== "string" || url.indexOf("https://") !== 0) {
    throw new DnsError("dns/bad-doh-url",
      "dns.useDnsOverHttps: url must be an https:// string, got " + JSON.stringify(url));
  }
  var method = opts.method;
  if (method !== undefined && method !== "GET" && method !== "POST") {
    throw new DnsError("dns/bad-doh-method",
      "dns.useDnsOverHttps: method must be 'GET' | 'POST' | undefined (auto), got " +
      JSON.stringify(method));
  }
  if (opts.ca !== undefined && opts.ca !== null &&
      !Buffer.isBuffer(opts.ca) && typeof opts.ca !== "string" && !Array.isArray(opts.ca)) {
    throw new DnsError("dns/bad-doh-ca",
      "dns.useDnsOverHttps: ca must be a PEM string, Buffer, or array of either");
  }
  STATE.doh = { url: url, method: method, ca: opts.ca || null };
  _clearCache();
  observability().safeEvent("network.dns.doh.set", 1, { url: url, method: method || "auto" });
}

function useDnsOverTls(opts) {
  opts = opts || {};
  validateOpts(opts, ["host", "port", "servername", "ca"], "dns.useDnsOverTls");
  validateOpts.requireNonEmptyString(opts.host, "dns.useDnsOverTls: host", DnsError, "dns/bad-dot-host");
  validateOpts.optionalPort(opts.port, "dns.useDnsOverTls: opts.port", DnsError, "dns/bad-dot-port");
  if (opts.ca !== undefined && opts.ca !== null &&
      !Buffer.isBuffer(opts.ca) && typeof opts.ca !== "string" && !Array.isArray(opts.ca)) {
    throw new DnsError("dns/bad-dot-ca",
      "dns.useDnsOverTls: ca must be a PEM string, Buffer, or array of either");
  }
  STATE.dot = {
    host:       opts.host,
    port:       opts.port || 853,
    servername: opts.servername || opts.host,
    ca:         opts.ca || null,
  };
  _resetDotPool();
  _clearCache();
  observability().safeEvent("network.dns.dot.set", 1, { host: STATE.dot.host, port: STATE.dot.port });
}

function _withTimeout(promise, ms, host) {
  if (ms <= 0) return promise;
  return new Promise(function (resolve, reject) {
    var timer = setTimeout(function () {
      reject(new DnsError("dns/lookup-timeout", "dns lookup of '" + host + "' exceeded " + ms + "ms"));
    }, ms);
    timer.unref && timer.unref();
    promise.then(
      function (v) { clearTimeout(timer); resolve(v); },
      function (e) { clearTimeout(timer); reject(e); }
    );
  });
}

function _encodeDnsQuery(host, qtype) {
  var parts = host.split(".").filter(Boolean);
  var nameLen = 1;
  for (var i = 0; i < parts.length; i++) nameLen += 1 + Buffer.byteLength(parts[i], "ascii");
  var buf = Buffer.alloc(12 + nameLen + 4);
  // Cryptographic RNG for the 16-bit DNS query ID — frustrates poisoning
  // attempts that guess the transaction ID. Routes through `b.crypto.randomInt`
  // (which wraps nodeCrypto.randomInt) so every framework random-int draw
  // is greppable through one substrate.
  var id = bCrypto.randomInt(0, 0x10000);
  buf.writeUInt16BE(id, 0);
  buf.writeUInt16BE(0x0100, 2);
  buf.writeUInt16BE(1, 4);
  var off = 12;
  for (var p = 0; p < parts.length; p++) {
    var s = parts[p];
    buf.writeUInt8(Buffer.byteLength(s, "ascii"), off++);
    off += buf.write(s, off, "ascii");
  }
  buf.writeUInt8(0, off++);
  buf.writeUInt16BE(qtype, off); off += 2;
  buf.writeUInt16BE(1, off);
  return { buf: buf, id: id };
}

// Walk a DNS-message name in-place and advance `state.off`. RFC 1035
// §3.1 names terminate either with a single 0x00 byte OR with a
// 2-byte compression pointer (high two bits 11). The pre-0.7.68
// parser unconditionally executed `if (buf[off] === 0) off++`
// after the loop, which consumed the high byte of the next field
// when the loop had exited via the compression pointer — silently
// breaking every DNS response that used name compression in the
// answer section (which is most of them).
function _skipDnsName(buf, state) {
  var endedViaPointer = false;
  while (state.off < buf.length && buf[state.off] !== 0) {
    if ((buf[state.off] & 0xc0) === 0xc0) {                                      // RFC 1035 name-compression pointer mask
      state.off += 2;
      endedViaPointer = true;
      break;
    }
    state.off += buf[state.off] + 1;
  }
  if (!endedViaPointer && state.off < buf.length && buf[state.off] === 0) {
    state.off += 1;
  }
}

function _decodeDnsAnswer(buf, qtype) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) throw new DnsError("dns/bad-reply", "dns reply truncated");
  var rcode = buf.readUInt8(3) & 0x0f;
  if (rcode !== 0) throw new DnsError("dns/no-result", "dns reply rcode " + rcode);
  var qdcount = buf.readUInt16BE(4);
  var ancount = buf.readUInt16BE(6);
  var state = { off: 12 };
  for (var q = 0; q < qdcount; q++) {
    _skipDnsName(buf, state);
    state.off += 4;
  }
  var addrs = [];
  for (var a = 0; a < ancount; a++) {
    _skipDnsName(buf, state);
    var off = state.off;
    var rtype  = buf.readUInt16BE(off); off += 2;
    off += 2;
    off += 4;
    var rdlen  = buf.readUInt16BE(off); off += 2;
    if (rtype === qtype && qtype === 1 && rdlen === 4) {
      addrs.push(buf[off] + "." + buf[off + 1] + "." + buf[off + 2] + "." + buf[off + 3]);
    } else if (rtype === qtype && qtype === DNS_QTYPE_AAAA && rdlen === IPV6_ADDR_BYTES) {
      var groups = [];
      for (var g = 0; g < IPV6_HEX_GROUPS; g++) {
        groups.push(buf.readUInt16BE(off + g * 2).toString(HEX_RADIX));
      }
      addrs.push(groups.join(":"));
    }
    off += rdlen;
    state.off = off;
  }
  return addrs;
}

// Read the AD bit (Authenticated Data, RFC 4035) from a DNS reply
// header. Byte 3 holds RA, Z, AD, CD, and rcode bits; AD is bit 5
// (mask 0x20). Set when the upstream recursive resolver has validated
// the chain.
function _readAdBit(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) return false;
  return (buf.readUInt8(3) & 0x20) !== 0;                                        // RFC 4035 AD-bit mask
}

// DoH GET URL length cap. RFC 8484 §4.1 says clients MAY use POST when
// the GET URL would exceed implementation limits. We pick 2048 bytes
// (a conservative ceiling well below RFC 7230's recommended 8 KB) so
// long DNS names (e.g. ESNI / SVCB record queries with operator-side
// hostname concatenation) fall back cleanly. Operator can force POST
// always with `useDnsOverHttps({ url, method: "POST" })`.
var DOH_GET_URL_MAX_BYTES = 2048;

async function _dohLookup(host, family) {
  var qtype = family === 6 ? 28 : 1;
  var enc = _encodeDnsQuery(host, qtype);
  var b64 = bCrypto.toBase64Url(enc.buf);
  var getUrl = STATE.doh.url + (STATE.doh.url.indexOf("?") === -1 ? "?" : "&") + "dns=" + b64;
  var forcedMethod = STATE.doh.method;
  var usePost = forcedMethod === "POST" || (!forcedMethod && getUrl.length > DOH_GET_URL_MAX_BYTES);
  // STATE.doh.url is already https-validated in useDnsOverHttps; route the
  // parse through safeUrl so the framework's URL primitive owns every parse.
  var u = safeUrl.parse(STATE.doh.url, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
  return new Promise(function (resolve, reject) {
    var reqOpts = {
      hostname:   u.hostname,
      port:       u.port || 443,
      path:       u.pathname + u.search,
      method:     usePost ? "POST" : "GET",
      headers:    {
        "accept": "application/dns-message",
      },
      minVersion: "TLSv1.3",
      ecdhCurve:  C.TLS_GROUP_CURVE_STR,
    };
    if (STATE.doh.ca) reqOpts.ca = STATE.doh.ca;
    if (usePost) {
      reqOpts.headers["content-type"]   = "application/dns-message";
      reqOpts.headers["content-length"] = enc.buf.length;
    } else {
      // getUrl was composed from STATE.doh.url + a base64-url DNS query suffix.
      // safeUrl.parse re-validates the composed URL.
      var parsedGet = safeUrl.parse(getUrl, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
      reqOpts.path = parsedGet.pathname + parsedGet.search;
    }
    var req = https.request(reqOpts, function (res) {
      // RFC 8484 caps DoH responses at 64 KiB practical max; raise to
      // 256 KiB to leave headroom for upstream resolvers that pad.
      var collector = safeBuffer.boundedChunkCollector({
        maxBytes:    C.BYTES.kib(256),
        errorClass:  DnsError,
        sizeCode:    "dns/doh-too-large",
        sizeMessage: "DoH response exceeds 256 KiB",
      });
      var pushFailed = null;
      res.on("data", function (c) {
        if (pushFailed) return;
        try { collector.push(c); }
        catch (e) { pushFailed = e; }
      });
      res.on("end", function () {
        try {
          if (pushFailed) { reject(pushFailed); return; }
          var body = collector.result();
          if (res.statusCode !== 200) {
            reject(new DnsError("dns/doh-http", "DoH HTTP " + res.statusCode + " for " + host));
            return;
          }
          resolve(_decodeDnsAnswer(body, qtype));
        } catch (e) { reject(e); }
      });
    });
    req.on("error", function (e) { reject(new DnsError("dns/doh-failed", "DoH request failed: " + e.message)); });
    if (usePost) req.write(enc.buf);
    req.end();
  });
}

// _dohLookupSecure — DNSSEC-aware DoH lookup. Returns `{ rrs, ad }`
// where `ad` is the AD bit (RFC 4035) set by the upstream resolver
// after chain validation. Internal — operators reach for
// `resolveSecure` instead.
async function _dohLookupSecure(host, family) {
  var qtype = family === 6 ? 28 : 1;                                             // DNS QTYPE values for A / AAAA
  var enc = _encodeDnsQuery(host, qtype);
  var b64 = bCrypto.toBase64Url(enc.buf);
  var getUrl = STATE.doh.url + (STATE.doh.url.indexOf("?") === -1 ? "?" : "&") + "dns=" + b64;
  var forcedMethod = STATE.doh.method;
  var usePost = forcedMethod === "POST" || (!forcedMethod && getUrl.length > DOH_GET_URL_MAX_BYTES);
  var u = safeUrl.parse(STATE.doh.url, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
  return new Promise(function (resolve, reject) {
    var reqOpts = {
      hostname:   u.hostname,
      port:       u.port || 443,                                                 // HTTPS default port
      path:       u.pathname + u.search,
      method:     usePost ? "POST" : "GET",
      headers:    { "accept": "application/dns-message" },
      minVersion: "TLSv1.3",
      ecdhCurve:  C.TLS_GROUP_CURVE_STR,
    };
    if (STATE.doh.ca) reqOpts.ca = STATE.doh.ca;
    if (usePost) {
      reqOpts.headers["content-type"]   = "application/dns-message";
      reqOpts.headers["content-length"] = enc.buf.length;
    } else {
      var parsedGet = safeUrl.parse(getUrl, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
      reqOpts.path = parsedGet.pathname + parsedGet.search;
    }
    var req = https.request(reqOpts, function (res) {
      var collector = safeBuffer.boundedChunkCollector({
        maxBytes:    C.BYTES.kib(256),
        errorClass:  DnsError,
        sizeCode:    "dns/doh-too-large",
        sizeMessage: "DoH response exceeds 256 KiB",
      });
      var pushFailed = null;
      res.on("data", function (c) {
        if (pushFailed) return;
        try { collector.push(c); }
        catch (e) { pushFailed = e; }
      });
      res.on("end", function () {
        try {
          if (pushFailed) { reject(pushFailed); return; }
          var body = collector.result();
          if (res.statusCode !== 200) {                                          // HTTP 200 OK
            reject(new DnsError("dns/doh-http", "DoH HTTP " + res.statusCode + " for " + host));
            return;
          }
          resolve({ rrs: _decodeDnsAnswer(body, qtype), ad: _readAdBit(body) });
        } catch (e) { reject(e); }
      });
    });
    req.on("error", function (e) { reject(new DnsError("dns/doh-failed", "DoH request failed: " + e.message)); });
    if (usePost) req.write(enc.buf);
    req.end();
  });
}

// resolveSecure — DNSSEC-aware resolution. Returns `{ rrs, ad }`
// where `ad` is the AD bit (RFC 4035) set by the upstream DoH
// resolver after chain validation, and `rrs` is the answer-record
// list (IPv4 / IPv6 string addresses for A / AAAA queries).
//
// Operators wiring DANE / TLSA validation (RFC 7672 SMTP DANE)
// require `ad === true` to honor the DANE security claim per RFC
// 7672 §1.3 — without DNSSEC validation the TLSA records can't be
// authenticated and the chain check is meaningless.
//
// Only available over DoH transport. The system resolver and DoT
// transports don't surface the AD bit through Node's API today.
async function resolveSecure(host, type) {
  type = type || "A";
  if (!STATE.doh) {
    throw new DnsError("dns/secure-requires-doh",
      "resolveSecure requires DoH transport (call useDnsOverHttps " +
      "or rely on the default-on DoH posture)");
  }
  if (typeof host !== "string" || host.length === 0 || host.length > 253) {     // RFC 1035 hostname octet ceiling
    throw new DnsError("dns/bad-host",
      "resolveSecure host is malformed");
  }
  // RFC 1035 §2.3.4 LDH validation — labels are letters / digits /
  // hyphen, hyphens not at edges, label length 1..63, total length
  // 253. Pre-v0.8.32 the framework only checked total length;
  // operator-supplied hosts containing `_` / `:` / spaces flowed
  // through to the DoH endpoint and surfaced as opaque server
  // errors.
  var labels = host.split(".");
  for (var li = 0; li < labels.length; li += 1) {
    var label = labels[li];
    if (label.length === 0 || label.length > 63) {                                            // RFC 1035 max label length
      throw new DnsError("dns/bad-host",
        "resolveSecure host has invalid label (length 1..63 required, got " + label.length + ")");
    }
    if (!/^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$/.test(label)) {
      throw new DnsError("dns/bad-host",
        "resolveSecure host label '" + label + "' violates RFC 1035 LDH rule (letters/digits/hyphen, no leading/trailing hyphen)");
    }
  }
  var family;
  if (type === "A")    family = 4;
  else if (type === "AAAA") family = 6;
  else throw new DnsError("dns/secure-unsupported-type",
    "resolveSecure currently supports A and AAAA; got " + type);
  return _dohLookupSecure(host, family);
}

// DoT connection pool. Per-(host:port) cached TLS socket so successive
// lookups amortize the handshake. Sockets idle past the timeout are
// closed and removed; first lookup after expiry rebuilds. Each socket
// services one in-flight query at a time (DNS-over-TCP allows pipelining
// but the framework chooses serialization for simpler back-pressure).
var DOT_IDLE_TIMEOUT_MS = C.TIME.minutes(2);
var _dotPool = new Map();           // "host:port" → { sock, lastUsedAt, idle, queue }

function _dotPoolKey() {
  return STATE.dot.host + ":" + STATE.dot.port;
}

function _dotConnect() {
  var connectOpts = {
    host:       STATE.dot.host,
    port:       STATE.dot.port,
    servername: STATE.dot.servername,
    minVersion: "TLSv1.3",
    ecdhCurve:  C.TLS_GROUP_CURVE_STR,
  };
  if (STATE.dot.ca) connectOpts.ca = STATE.dot.ca;
  var sock = nodeTls.connect(connectOpts);
  // The pool entry is ref()'d while a query is in flight and unref()'d
  // when idle — _dotLookup toggles this around its query. Calling
  // unref() unconditionally here let node exit during a normal lookup
  // when no other I/O kept the event loop alive.
  return sock;
}

function _dotEvict(key) {
  var entry = _dotPool.get(key);
  if (!entry) return;
  try { entry.sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
  _dotPool.delete(key);
}

async function _dotLookup(host, family) {
  var qtype = family === 6 ? 28 : 1;
  var enc = _encodeDnsQuery(host, qtype);
  var key = _dotPoolKey();
  var entry = _dotPool.get(key);
  if (entry && (Date.now() - entry.lastUsedAt > DOT_IDLE_TIMEOUT_MS)) {
    _dotEvict(key);
    entry = null;
  }
  if (!entry) {
    var sock = _dotConnect();
    entry = {
      sock:       sock,
      lastUsedAt: Date.now(),
      idle:       true,
      ready:      new Promise(function (res, rej) {
        sock.once("secureConnect", function () { res(); });
        sock.once("error", function (e) {
          rej(new DnsError("dns/dot-handshake-failed",
            "DoT TLS handshake to " + STATE.dot.host + ":" + STATE.dot.port +
            " failed: " + ((e && e.message) || String(e))));
        });
      }),
    };
    // Pre-attach a no-op observer so a handshake failure isn't reported
    // as an unhandledRejection in the window between this assignment
    // and the first lookup awaiting entry.ready. The real reject path
    // routes through _dotLookup's then(_, onErr) handler below.
    entry.ready.catch(function () { /* observed; routed via per-lookup handler */ });
    _dotPool.set(key, entry);
    sock.on("error", function () { _dotEvict(key); });
    sock.on("close", function () { if (_dotPool.get(key) === entry) _dotPool.delete(key); });
  }
  // Serialize: each socket handles one query at a time. If another
  // query is in flight, queue behind it.
  var waitTicket = entry._tail || Promise.resolve();
  entry._tail = waitTicket.then(function () {
    return new Promise(function (resolve, reject) {
      entry.idle = false;
      // Hold the event loop open while a query is in flight.
      try { entry.sock.ref(); } catch (_e) { /* best-effort event-loop hold */ }
      Promise.resolve(entry.ready).then(function () {
        var lenBuf = Buffer.alloc(2);
        lenBuf.writeUInt16BE(enc.buf.length, 0);
        var got = [];
        var expectLen = -1;
        var done = false;
        function settle(err, val) {
          if (done) return;
          done = true;
          entry.sock.removeListener("data", onData);
          entry.sock.removeListener("error", onErr);
          entry.idle = true;
          entry.lastUsedAt = Date.now();
          // Release the event-loop hold so an idle pool socket doesn't
          // keep node alive between queries.
          try { entry.sock.unref(); } catch (_e) { /* best-effort event-loop release */ }
          if (err) reject(err); else resolve(val);
        }
        function onData(chunk) {
          got.push(chunk);
          var all = Buffer.concat(got);
          if (expectLen === -1 && all.length >= 2) expectLen = all.readUInt16BE(0);
          if (expectLen >= 0 && all.length >= expectLen + 2) {
            try {
              settle(null, _decodeDnsAnswer(all.slice(2, 2 + expectLen), qtype));
            } catch (e) { settle(e); }
          }
        }
        function onErr(e) {
          _dotEvict(key);
          settle(new DnsError("dns/dot-failed", "DoT failed: " + e.message));
        }
        entry.sock.on("data", onData);
        entry.sock.on("error", onErr);
        entry.sock.write(lenBuf);
        entry.sock.write(enc.buf);
      }, function (handshakeErr) {
        // entry.ready rejected (TLS handshake / cert verification failure).
        // Route as the lookup's reject so callers see a real DnsError
        // instead of an unhandledRejection from the TLSSocket event.
        entry.idle = true;
        try { entry.sock.unref(); } catch (_e) { /* best-effort event-loop release */ }
        reject(handshakeErr);
      });
    });
  });
  return entry._tail;
}

function _resetDotPool() {
  var keys = Array.from(_dotPool.keys());
  for (var i = 0; i < keys.length; i++) _dotEvict(keys[i]);
}

// ---- Generic DNS query (arbitrary QTYPE) -----------------------------
//
// The pre-v0.8.53 DNS module only handled A (1) and AAAA (28) lookups.
// SVCB (64) / HTTPS (65) and the DDR / DNR discovery primitives need a
// path that sends an arbitrary QTYPE and returns the raw rdata buffers
// for downstream parsing. These helpers reuse the existing encode +
// transport infrastructure (DoH / DoT / system) and add a small
// rdata-aware decoder that walks the answer section preserving the
// rdata bytes and answer offsets (needed because SVCB rdata contains
// compressed names that point back into the message).
//
// NOT IN SCOPE — DoQ (DNS-over-QUIC, RFC 9250). Node's QUIC support is
// experimental as of Node 24.x (tracking issue
// https://github.com/nodejs/node/issues/38478) and the framework's
// "no flag-gated experimental APIs in defaults" policy keeps it
// deferred. Operators wanting DoQ today wire it in their own agent
// and feed the returned IP set back through the existing transport
// abstractions (DDR-discovered DoH / DoT). Re-evaluate when Node
// flips QUIC stable.

// RFC 1035 §4.1.4 name compression — read a possibly-compressed name
// starting at `start`. Returns { name, nextOff } where nextOff is the
// byte immediately after the name's length-prefixed encoding (NOT
// chasing the pointer). `name` is a dot-joined string (without the
// trailing root label). Hardened against pointer loops with an
// iteration cap.
function _readDnsName(buf, start) {
  var labels = [];
  var off = start;
  var nextOff = -1;
  var iterations = 0;
  var ITER_CAP = 256;                                                            // DNS name pointer-loop safeguard
  while (off < buf.length && iterations < ITER_CAP) {
    iterations += 1;
    var len = buf[off];
    if (len === 0) {
      if (nextOff === -1) nextOff = off + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {                                                 // RFC 1035 name-compression pointer mask
      if (off + 1 >= buf.length) {
        throw new DnsError("dns/svcb-malformed",
          "DNS name truncated at compression pointer");
      }
      if (nextOff === -1) nextOff = off + 2;
      var ptr = ((len & 0x3f) << 8) | buf[off + 1];                              // RFC 1035 pointer offset mask
      if (ptr >= buf.length || ptr === off) {
        throw new DnsError("dns/svcb-malformed",
          "DNS name pointer out of bounds or self-referential");
      }
      off = ptr;
      continue;
    }
    if ((len & 0xc0) !== 0) {                                                    // RFC 1035 reserved label-type bits
      throw new DnsError("dns/svcb-malformed",
        "DNS name has reserved label type 0x" + len.toString(HEX_RADIX));
    }
    if (off + 1 + len > buf.length) {
      throw new DnsError("dns/svcb-malformed",
        "DNS name label exceeds message length");
    }
    labels.push(buf.toString("ascii", off + 1, off + 1 + len));
    off += 1 + len;
  }
  if (iterations >= ITER_CAP) {
    throw new DnsError("dns/svcb-malformed",
      "DNS name compression loop (>" + ITER_CAP + " hops)");
  }
  if (nextOff === -1) {
    throw new DnsError("dns/svcb-malformed",
      "DNS name not terminated");
  }
  return { name: labels.join("."), nextOff: nextOff };
}

// Walk the answer section preserving rdata offsets so SVCB rdata can
// resolve compressed names against the full message buffer.
function _decodeDnsAnswerRaw(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 12) {
    throw new DnsError("dns/bad-reply", "dns reply truncated");
  }
  var rcode = buf.readUInt8(3) & 0x0f;                                           // RFC 1035 RCODE nibble mask
  if (rcode !== 0) {
    throw new DnsError("dns/no-result", "dns reply rcode " + rcode);
  }
  var qdcount = buf.readUInt16BE(4);
  var ancount = buf.readUInt16BE(6);
  var state = { off: 12 };
  for (var q = 0; q < qdcount; q++) {
    _skipDnsName(buf, state);
    state.off += 4;
  }
  var answers = [];
  for (var a = 0; a < ancount; a++) {
    _skipDnsName(buf, state);
    var off = state.off;
    if (off + 10 > buf.length) {
      throw new DnsError("dns/bad-reply", "answer record truncated");
    }
    var rtype = buf.readUInt16BE(off); off += 2;
    var rclass = buf.readUInt16BE(off); off += 2;
    var ttl = buf.readUInt32BE(off); off += 4;
    var rdlen = buf.readUInt16BE(off); off += 2;
    if (off + rdlen > buf.length) {
      throw new DnsError("dns/bad-reply", "answer rdata truncated");
    }
    answers.push({
      rtype:    rtype,
      rclass:   rclass,
      ttl:      ttl,
      rdataOff: off,
      rdlen:    rdlen,
    });
    off += rdlen;
    state.off = off;
  }
  return { msg: buf, answers: answers, ad: _readAdBit(buf) };
}

async function _dohRawQuery(host, qtype) {
  var enc = _encodeDnsQuery(host, qtype);
  var b64 = bCrypto.toBase64Url(enc.buf);
  var getUrl = STATE.doh.url + (STATE.doh.url.indexOf("?") === -1 ? "?" : "&") + "dns=" + b64;
  var forcedMethod = STATE.doh.method;
  var usePost = forcedMethod === "POST" || (!forcedMethod && getUrl.length > DOH_GET_URL_MAX_BYTES);
  var u = safeUrl.parse(STATE.doh.url, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
  return new Promise(function (resolve, reject) {
    var reqOpts = {
      hostname:   u.hostname,
      port:       u.port || 443,                                                 // HTTPS default port
      path:       u.pathname + u.search,
      method:     usePost ? "POST" : "GET",
      headers:    { "accept": "application/dns-message" },
      minVersion: "TLSv1.3",
      ecdhCurve:  C.TLS_GROUP_CURVE_STR,
    };
    if (STATE.doh.ca) reqOpts.ca = STATE.doh.ca;
    if (usePost) {
      reqOpts.headers["content-type"]   = "application/dns-message";
      reqOpts.headers["content-length"] = enc.buf.length;
    } else {
      var parsedGet = safeUrl.parse(getUrl, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
      reqOpts.path = parsedGet.pathname + parsedGet.search;
    }
    var req = https.request(reqOpts, function (res) {
      var collector = safeBuffer.boundedChunkCollector({
        maxBytes:    C.BYTES.kib(256),
        errorClass:  DnsError,
        sizeCode:    "dns/doh-too-large",
        sizeMessage: "DoH response exceeds 256 KiB",
      });
      var pushFailed = null;
      res.on("data", function (c) {
        if (pushFailed) return;
        try { collector.push(c); }
        catch (e) { pushFailed = e; }
      });
      res.on("end", function () {
        try {
          if (pushFailed) { reject(pushFailed); return; }
          if (res.statusCode !== 200) {                                          // HTTP 200 OK
            reject(new DnsError("dns/doh-http", "DoH HTTP " + res.statusCode + " for " + host));
            return;
          }
          resolve(collector.result());
        } catch (e) { reject(e); }
      });
    });
    req.on("error", function (e) { reject(new DnsError("dns/doh-failed", "DoH request failed: " + e.message)); });
    if (usePost) req.write(enc.buf);
    req.end();
  });
}

async function _dotRawQuery(host, qtype) {
  var enc = _encodeDnsQuery(host, qtype);
  var key = _dotPoolKey();
  var entry = _dotPool.get(key);
  if (entry && (Date.now() - entry.lastUsedAt > DOT_IDLE_TIMEOUT_MS)) {
    _dotEvict(key);
    entry = null;
  }
  if (!entry) {
    var sock = _dotConnect();
    entry = {
      sock:       sock,
      lastUsedAt: Date.now(),
      idle:       true,
      ready:      new Promise(function (res, rej) {
        sock.once("secureConnect", function () { res(); });
        sock.once("error", function (e) {
          rej(new DnsError("dns/dot-handshake-failed",
            "DoT TLS handshake to " + STATE.dot.host + ":" + STATE.dot.port +
            " failed: " + ((e && e.message) || String(e))));
        });
      }),
    };
    entry.ready.catch(function () { /* observed via per-lookup handler below */ });
    _dotPool.set(key, entry);
    sock.on("error", function () { _dotEvict(key); });
    sock.on("close", function () { if (_dotPool.get(key) === entry) _dotPool.delete(key); });
  }
  var waitTicket = entry._tail || Promise.resolve();
  entry._tail = waitTicket.then(function () {
    return new Promise(function (resolve, reject) {
      entry.idle = false;
      try { entry.sock.ref(); } catch (_e) { /* best-effort event-loop hold */ }
      Promise.resolve(entry.ready).then(function () {
        var lenBuf = Buffer.alloc(2);
        lenBuf.writeUInt16BE(enc.buf.length, 0);
        var got = [];
        var expectLen = -1;
        var done = false;
        function settle(err, val) {
          if (done) return;
          done = true;
          entry.sock.removeListener("data", onData);
          entry.sock.removeListener("error", onErr);
          entry.idle = true;
          entry.lastUsedAt = Date.now();
          try { entry.sock.unref(); } catch (_e) { /* best-effort event-loop release */ }
          if (err) reject(err); else resolve(val);
        }
        function onData(chunk) {
          got.push(chunk);
          var all = Buffer.concat(got);
          if (expectLen === -1 && all.length >= 2) expectLen = all.readUInt16BE(0);
          if (expectLen >= 0 && all.length >= expectLen + 2) {
            settle(null, all.slice(2, 2 + expectLen));
          }
        }
        function onErr(e) {
          _dotEvict(key);
          settle(new DnsError("dns/dot-failed", "DoT failed: " + e.message));
        }
        entry.sock.on("data", onData);
        entry.sock.on("error", onErr);
        entry.sock.write(lenBuf);
        entry.sock.write(enc.buf);
      }, function (handshakeErr) {
        entry.idle = true;
        try { entry.sock.unref(); } catch (_e) { /* best-effort event-loop release */ }
        reject(handshakeErr);
      });
    });
  });
  return entry._tail;
}

async function _systemRawQuery(host, qtype) {
  // node:dns doesn't expose arbitrary-QTYPE wire-format queries; fall
  // back to TCP framed query against the configured system resolvers
  // (port 53). Used only when the operator has explicitly opted out
  // of DoH/DoT via useSystemResolver().
  var servers = getServers();
  if (servers.length === 0) {
    throw new DnsError("dns/no-system-resolvers",
      "system resolver has no configured servers; cannot send raw QTYPE query");
  }
  var serverEntry = servers[0];
  var serverHost = serverEntry;
  var serverPort = 53;                                                           // IANA-assigned DNS port
  var bracketEnd = serverEntry.lastIndexOf("]:");
  if (bracketEnd !== -1) {
    serverHost = serverEntry.slice(1, bracketEnd);
    serverPort = parseInt(serverEntry.slice(bracketEnd + 2), 10) || 53;          // IANA-assigned DNS port
  } else if (serverEntry.indexOf(":") !== -1 && net.isIP(serverEntry) === 0) {
    var colonIdx = serverEntry.lastIndexOf(":");
    serverHost = serverEntry.slice(0, colonIdx);
    serverPort = parseInt(serverEntry.slice(colonIdx + 1), 10) || 53;            // IANA-assigned DNS port
  }
  var enc = _encodeDnsQuery(host, qtype);
  return new Promise(function (resolve, reject) {
    var sock = net.connect({ host: serverHost, port: serverPort });
    var got = [];
    var expectLen = -1;
    var done = false;
    function settle(err, val) {
      if (done) return;
      done = true;
      try { sock.destroy(); } catch (_e) { /* best-effort socket teardown */ }
      if (err) reject(err); else resolve(val);
    }
    sock.on("connect", function () {
      var lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16BE(enc.buf.length, 0);
      sock.write(lenBuf);
      sock.write(enc.buf);
    });
    sock.on("data", function (chunk) {
      got.push(chunk);
      var all = Buffer.concat(got);
      if (expectLen === -1 && all.length >= 2) expectLen = all.readUInt16BE(0);
      if (expectLen >= 0 && all.length >= expectLen + 2) {
        settle(null, all.slice(2, 2 + expectLen));
      }
    });
    sock.on("error", function (e) {
      settle(new DnsError("dns/system-failed", "system DNS TCP query failed: " + e.message));
    });
    sock.on("close", function () {
      if (!done) settle(new DnsError("dns/system-failed", "system DNS TCP closed before reply"));
    });
  });
}

// Pick a transport for raw-QTYPE queries based on operator config.
// `forceTransport` (used by DDR) overrides; "system" routes through
// the OS resolver.
async function _rawQuery(host, qtype, forceTransport) {
  _ensureSecureDefault();
  var transport = forceTransport;
  if (!transport) {
    if (STATE.doh) transport = "doh";
    else if (STATE.dot) transport = "dot";
    else transport = "system";
  }
  if (transport === "doh") {
    if (!STATE.doh) {
      throw new DnsError("dns/transport-unavailable",
        "raw query requested DoH transport but useDnsOverHttps() not configured");
    }
    return _withTimeout(_dohRawQuery(host, qtype), STATE.lookupTimeoutMs, host);
  }
  if (transport === "dot") {
    if (!STATE.dot) {
      throw new DnsError("dns/transport-unavailable",
        "raw query requested DoT transport but useDnsOverTls() not configured");
    }
    return _withTimeout(_dotRawQuery(host, qtype), STATE.lookupTimeoutMs, host);
  }
  if (transport === "system") {
    return _withTimeout(_systemRawQuery(host, qtype), STATE.lookupTimeoutMs, host);
  }
  throw new DnsError("dns/bad-transport",
    "raw query: unknown transport '" + transport + "' (expected 'doh' | 'dot' | 'system')");
}

// ---- SVCB / HTTPS RR (RFC 9460) --------------------------------------

var DNS_QTYPE_SVCB  = 64;                                                        // RFC 9460 §14.1 SVCB record type code
var DNS_QTYPE_HTTPS = 65;                                                        // RFC 9460 §14.1 HTTPS record type code

// SvcParamKey assignments (RFC 9460 §14.3.2 + IANA registry). Keys
// past 7 are operator-extensible; we recognize the IETF-blessed set
// and surface the rest as opaque buffers under params.unknown[<key>].
var SVCB_KEY_MANDATORY    = 0;
var SVCB_KEY_ALPN         = 1;
var SVCB_KEY_NO_DEF_ALPN  = 2;
var SVCB_KEY_PORT         = 3;
var SVCB_KEY_IPV4HINT     = 4;
var SVCB_KEY_ECH          = 5;
var SVCB_KEY_IPV6HINT     = 6;
var SVCB_KEY_DOHPATH      = 7;                                                   // RFC 9461 SvcParamKey

function _readCharString(buf, off, end) {
  if (off >= end) {
    throw new DnsError("dns/svcb-malformed", "alpn list truncated at char-string length");
  }
  var len = buf[off];
  if (off + 1 + len > end) {
    throw new DnsError("dns/svcb-malformed", "alpn char-string overflows alpn value");
  }
  return { value: buf.toString("utf8", off + 1, off + 1 + len), nextOff: off + 1 + len };
}

function _parseSvcbRdata(msg, rdataOff, rdlen) {
  var end = rdataOff + rdlen;
  if (rdataOff + 2 > end) {
    throw new DnsError("dns/svcb-malformed", "SVCB rdata truncated before priority");
  }
  var priority = msg.readUInt16BE(rdataOff);
  var nameRes = _readDnsName(msg, rdataOff + 2);
  var target = nameRes.name === "" ? "." : nameRes.name;
  var off = nameRes.nextOff;
  var params = {};
  var prevKey = -1;
  while (off < end) {
    if (off + 4 > end) {
      throw new DnsError("dns/svcb-malformed", "SvcParam header truncated");
    }
    var key = msg.readUInt16BE(off); off += 2;
    var paramLen = msg.readUInt16BE(off); off += 2;
    if (off + paramLen > end) {
      throw new DnsError("dns/svcb-malformed", "SvcParam value overflows rdata");
    }
    if (key <= prevKey) {
      throw new DnsError("dns/svcb-malformed",
        "SvcParams not in ascending key order (key " + key + " after " + prevKey + ")");
    }
    prevKey = key;
    var paramEnd = off + paramLen;
    if (key === SVCB_KEY_MANDATORY) {
      if (paramLen % 2 !== 0) {
        throw new DnsError("dns/svcb-malformed", "mandatory SvcParam length not multiple of 2");
      }
      var mand = [];
      for (var mo = off; mo < paramEnd; mo += 2) {
        mand.push(msg.readUInt16BE(mo));
      }
      params.mandatory = mand;
    } else if (key === SVCB_KEY_ALPN) {
      var alpns = [];
      var ao = off;
      while (ao < paramEnd) {
        var cs = _readCharString(msg, ao, paramEnd);
        alpns.push(cs.value);
        ao = cs.nextOff;
      }
      params.alpn = alpns;
    } else if (key === SVCB_KEY_NO_DEF_ALPN) {
      if (paramLen !== 0) {
        throw new DnsError("dns/svcb-malformed", "no-default-alpn must have zero-length value");
      }
      params.noDefaultAlpn = true;
    } else if (key === SVCB_KEY_PORT) {
      if (paramLen !== 2) {
        throw new DnsError("dns/svcb-malformed", "port SvcParam must be 2 bytes");
      }
      params.port = msg.readUInt16BE(off);
    } else if (key === SVCB_KEY_IPV4HINT) {
      if (paramLen % 4 !== 0) {
        throw new DnsError("dns/svcb-malformed", "ipv4hint length not multiple of 4");
      }
      var v4 = [];
      for (var v4o = off; v4o < paramEnd; v4o += 4) {
        v4.push(msg[v4o] + "." + msg[v4o + 1] + "." + msg[v4o + 2] + "." + msg[v4o + 3]);
      }
      params.ipv4hint = v4;
    } else if (key === SVCB_KEY_ECH) {
      // ECHConfigList — opaque to the caller; surface as raw buffer.
      params.ech = Buffer.from(msg.slice(off, paramEnd));
    } else if (key === SVCB_KEY_IPV6HINT) {
      if (paramLen % IPV6_ADDR_BYTES !== 0) {
        throw new DnsError("dns/svcb-malformed", "ipv6hint length not multiple of 16");
      }
      var v6 = [];
      for (var v6o = off; v6o < paramEnd; v6o += IPV6_ADDR_BYTES) {
        var groups = [];
        for (var g = 0; g < IPV6_HEX_GROUPS; g++) {
          groups.push(msg.readUInt16BE(v6o + g * 2).toString(HEX_RADIX));
        }
        v6.push(groups.join(":"));
      }
      params.ipv6hint = v6;
    } else if (key === SVCB_KEY_DOHPATH) {
      params.dohpath = msg.toString("utf8", off, paramEnd);
    } else {
      // Unknown / future SvcParamKey — surface as opaque bytes so the
      // operator can still read it without us silently dropping the
      // record.
      if (!params.unknown) params.unknown = {};
      params.unknown[key] = Buffer.from(msg.slice(off, paramEnd));
    }
    off = paramEnd;
  }
  return { priority: priority, target: target, params: params };
}

function _validateLdh(host, primitive) {
  if (typeof host !== "string" || host.length === 0 || host.length > 253) {     // RFC 1035 hostname octet ceiling
    throw new DnsError("dns/bad-host",
      primitive + ": host must be a non-empty RFC 1035 LDH name (length 1..253)");
  }
  // Allow leading underscore on labels (SVCB / HTTPS query targets like
  // "_dns.resolver.arpa" require it).
  var labels = host.split(".");
  for (var li = 0; li < labels.length; li += 1) {
    var label = labels[li];
    if (label.length === 0 || label.length > 63) {                                            // RFC 1035 max label length
      throw new DnsError("dns/bad-host",
        primitive + ": host label length must be 1..63");
    }
    if (!/^[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$/.test(label)) {
      throw new DnsError("dns/bad-host",
        primitive + ": host label '" + label + "' violates LDH (allowed: letters/digits/underscore/hyphen, no leading/trailing hyphen)");
    }
  }
}

async function _querySvcbLike(host, qtype, opts) {
  opts = opts || {};
  validateOpts(opts, ["transport"], "dns.querySvcb");
  _validateLdh(host, "dns.querySvcb");
  if (opts.transport !== undefined && opts.transport !== "doh" &&
      opts.transport !== "dot" && opts.transport !== "system") {
    throw new DnsError("dns/bad-transport",
      "dns.querySvcb: transport must be 'doh' | 'dot' | 'system' | undefined");
  }
  observability().safeEvent("network.dns.svcb.requested", 1, { qtype: qtype, transport: opts.transport || "auto" });
  var startMs = _now();
  var reply;
  try {
    reply = await _rawQuery(host, qtype, opts.transport);
  } catch (e) {
    observability().safeEvent("network.dns.svcb.failure", 1, {
      latencyMs: _now() - startMs,
      code:      e.code || "unknown",
    });
    throw e;
  }
  var decoded = _decodeDnsAnswerRaw(reply);
  var records = [];
  for (var i = 0; i < decoded.answers.length; i++) {
    var ans = decoded.answers[i];
    if (ans.rtype !== qtype) continue;
    records.push(_parseSvcbRdata(decoded.msg, ans.rdataOff, ans.rdlen));
  }
  records.sort(function (a, b) { return a.priority - b.priority; });
  observability().safeEvent("network.dns.svcb.success", 1, {
    latencyMs: _now() - startMs,
    count:     records.length,
    qtype:     qtype,
  });
  return records;
}

/**
 * @primitive b.network.dns.querySvcb
 * @signature b.network.dns.querySvcb(name, opts?)
 * @since     0.8.53
 * @status    stable
 * @related   b.network.dns.queryHttps, b.network.dns.discoverEncrypted
 *
 * Query SVCB records (RFC 9460 §2) for `name`. Returns an array of
 * `{ priority, target, params }` records sorted by priority. AliasMode
 * records (priority === 0) carry a `target` and empty `params` —
 * the caller chases the alias by re-querying the target. ServiceMode
 * records (priority > 0) carry SvcParams: `alpn` / `port` / `ipv4hint` /
 * `ipv6hint` / `ech` / `mandatory` / `dohpath`. Unknown SvcParamKeys
 * surface under `params.unknown[key]` as raw bytes — operators
 * implementing forward-compat can still read them. Malformed rdata
 * throws `DnsError` with code `dns/svcb-malformed`.
 *
 * @opts
 *   {
 *     transport: "doh" | "dot" | "system",
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var rrs = await b.network.dns.querySvcb("_443._wss.example.com");
 */
async function querySvcb(name, opts) {
  return _querySvcbLike(name, DNS_QTYPE_SVCB, opts);
}

/**
 * @primitive b.network.dns.queryHttps
 * @signature b.network.dns.queryHttps(name, opts?)
 * @since     0.8.53
 * @status    stable
 * @related   b.network.dns.querySvcb
 *
 * Query HTTPS records (RFC 9460 §9). Identical to `querySvcb` except
 * the QTYPE is HTTPS (65) — the user-agent-facing variant of SVCB
 * for `https://` origins. Browsers query this for ECH discovery and
 * h3 advertisement; servers can call it to validate their own
 * published HTTPS RRset. Returns the same shape as `querySvcb`.
 *
 * @opts
 *   {
 *     transport: "doh" | "dot" | "system",
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var rrs = await b.network.dns.queryHttps("example.com");
 */
async function queryHttps(name, opts) {
  return _querySvcbLike(name, DNS_QTYPE_HTTPS, opts);
}

// ---- DDR / DNR (RFC 9462 + RFC 9463) ---------------------------------

// Default DDR query target — RFC 9462 §3.
var DDR_QUERY_NAME = "_dns.resolver.arpa";

// Operator-supplied designated resolver list. When set, the framework
// prefers these over its own configured transport (subject to
// `useDesignatedResolvers` having been called explicitly — never
// silently overriding operator config).
var _designatedResolvers = null;

/**
 * @primitive b.network.dns.discoverEncrypted
 * @signature b.network.dns.discoverEncrypted(opts?)
 * @since     0.8.53
 * @status    stable
 * @related   b.network.dns.useDesignatedResolvers, b.network.dns.querySvcb
 *
 * RFC 9462 Discovery of Designated Resolvers. Queries
 * `_dns.resolver.arpa` for SVCB records that advertise encrypted DNS
 * alternatives (DoH / DoT) hosted by the network's currently-configured
 * Do53 resolver. Returns a list of resolver descriptors with
 * `{ transport, alpn, target, port, dohpath, ipv4hint, ipv6hint, priority }`.
 *
 * The discovery query goes through the system resolver by default
 * (RFC 9462 §4 — DDR validation requires the response to come from
 * the Do53 resolver whose IP we compare). Callers that already have
 * a trusted DoH / DoT transport configured can pass
 * `{ insecureSystemResolverOnly: false }` to allow DDR via the
 * encrypted transport too.
 *
 * Throws `DnsError` with code `dns/ddr-not-discovered` when the
 * resolver does not publish DDR records.
 *
 * @opts
 *   {
 *     name:                       string,
 *     insecureSystemResolverOnly: boolean,
 *   }
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var resolvers = await b.network.dns.discoverEncrypted();
 */
async function discoverEncrypted(opts) {
  opts = opts || {};
  validateOpts(opts, ["name", "insecureSystemResolverOnly"], "dns.discoverEncrypted");
  var name = opts.name || DDR_QUERY_NAME;
  if (typeof name !== "string" || name.length === 0) {
    throw new DnsError("dns/bad-host",
      "dns.discoverEncrypted: name must be a non-empty string");
  }
  var insecureOnly = opts.insecureSystemResolverOnly !== false;
  var transport = insecureOnly ? "system" : undefined;
  _validateLdh(name, "dns.discoverEncrypted");
  var startMs = _now();
  var records;
  try {
    records = await _querySvcbLike(name, DNS_QTYPE_SVCB, { transport: transport });
  } catch (e) {
    observability().safeEvent("network.dns.ddr.failure", 1, {
      latencyMs: _now() - startMs,
      code:      e.code || "unknown",
    });
    if (e.code === "dns/no-result") {
      throw new DnsError("dns/ddr-not-discovered",
        "dns.discoverEncrypted: resolver did not publish DDR records at " + name);
    }
    throw e;
  }
  if (records.length === 0) {
    observability().safeEvent("network.dns.ddr.empty", 1, { latencyMs: _now() - startMs });
    throw new DnsError("dns/ddr-not-discovered",
      "dns.discoverEncrypted: resolver returned empty DDR record set at " + name);
  }
  var resolvers = [];
  for (var i = 0; i < records.length; i++) {
    var rec = records[i];
    if (rec.priority === 0) continue;        // AliasMode — caller chases
    var alpn = (rec.params && rec.params.alpn) || [];
    var isDot = alpn.indexOf("dot") !== -1;
    var isDoh = alpn.indexOf("h2") !== -1 || alpn.indexOf("h3") !== -1 ||
                (rec.params && typeof rec.params.dohpath === "string");
    var transportKind = isDot ? "dot" : (isDoh ? "doh" : null);
    if (!transportKind) continue;
    resolvers.push({
      transport: transportKind,
      alpn:      alpn,
      target:    rec.target,
      port:      (rec.params && rec.params.port) ||
                 (transportKind === "dot" ? 853 : 443),                          // IANA-assigned DoT/HTTPS ports
      dohpath:   (rec.params && rec.params.dohpath) || null,
      ipv4hint:  (rec.params && rec.params.ipv4hint) || [],
      ipv6hint:  (rec.params && rec.params.ipv6hint) || [],
      priority:  rec.priority,
    });
  }
  resolvers.sort(function (a, b) { return a.priority - b.priority; });
  if (resolvers.length === 0) {
    throw new DnsError("dns/ddr-not-discovered",
      "dns.discoverEncrypted: DDR records present but none advertised a recognized transport (alpn=dot/h2/h3)");
  }
  observability().safeEvent("network.dns.ddr.success", 1, {
    latencyMs: _now() - startMs,
    count:     resolvers.length,
  });
  return resolvers;
}

/**
 * @primitive b.network.dns.useDesignatedResolvers
 * @signature b.network.dns.useDesignatedResolvers(list)
 * @since     0.8.53
 * @status    stable
 * @related   b.network.dns.discoverEncrypted, b.network.dns.querySvcb
 *
 * RFC 9463 Discovery of Network-designated Resolvers. The framework
 * doesn't run a DHCP / IPv6 RA client itself; an operator-side agent
 * (or the output of `discoverEncrypted()`) supplies the resolver list
 * and the framework swaps its transport over to the lowest-priority
 * entry. Items are tried in order: the first one that successfully
 * configures (DoH `useDnsOverHttps`, DoT `useDnsOverTls`) wins.
 *
 * Each entry shape:
 *
 *   {
 *     transport: "doh" | "dot",
 *     url:       string,
 *     host:      string,
 *     port:      number,
 *     servername: string,
 *     alpn:      Array<string>,
 *     ca:        string|Buffer|Array,
 *   }
 *
 * Throws `DnsError` with code `dns/dnr-no-resolvers` if `list` is
 * empty, and `dns/dnr-malformed` if an entry is missing its required
 * transport-specific fields.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var found = await b.network.dns.discoverEncrypted();
 *   b.network.dns.useDesignatedResolvers(found.map(function (r) {
 *     return r.transport === "doh"
 *       ? { transport: "doh", url: "https://" + r.target + (r.dohpath || "/dns-query") }
 *       : { transport: "dot", host: r.target, port: r.port, servername: r.target };
 *   }));
 */
function useDesignatedResolvers(list) {
  if (!Array.isArray(list) || list.length === 0) {
    throw new DnsError("dns/dnr-no-resolvers",
      "dns.useDesignatedResolvers: expected non-empty array of resolver descriptors");
  }
  var validated = [];
  for (var i = 0; i < list.length; i++) {
    var entry = list[i];
    if (!entry || typeof entry !== "object") {
      throw new DnsError("dns/dnr-malformed",
        "dns.useDesignatedResolvers[" + i + "]: entry must be an object");
    }
    if (entry.transport !== "doh" && entry.transport !== "dot") {
      throw new DnsError("dns/dnr-malformed",
        "dns.useDesignatedResolvers[" + i + "]: transport must be 'doh' or 'dot'");
    }
    if (entry.transport === "doh") {
      if (typeof entry.url !== "string" || entry.url.indexOf("https://") !== 0) {
        throw new DnsError("dns/dnr-malformed",
          "dns.useDesignatedResolvers[" + i + "]: doh entry requires url starting with https://");
      }
    } else {
      if (typeof entry.host !== "string" || entry.host.length === 0) {
        throw new DnsError("dns/dnr-malformed",
          "dns.useDesignatedResolvers[" + i + "]: dot entry requires host");
      }
    }
    validated.push(entry);
  }
  var lastErr = null;
  for (var j = 0; j < validated.length; j++) {
    var v = validated[j];
    try {
      if (v.transport === "doh") {
        useDnsOverHttps({ url: v.url, ca: v.ca || null, method: v.method });
      } else {
        useDnsOverTls({
          host:       v.host,
          port:       v.port || 853,                                             // IANA-assigned DoT port
          servername: v.servername || v.host,
          ca:         v.ca || null,
        });
      }
      _designatedResolvers = validated.slice();
      observability().safeEvent("network.dns.dnr.set", 1, {
        count:     validated.length,
        active:    j,
        transport: v.transport,
      });
      return { active: j, count: validated.length };
    } catch (e) {
      lastErr = e;
      observability().safeEvent("network.dns.dnr.entry_failed", 1, {
        index:     j,
        transport: v.transport,
        code:      e.code || "unknown",
      });
    }
  }
  throw new DnsError("dns/dnr-no-resolvers",
    "dns.useDesignatedResolvers: no entry could be configured. Last error: " +
    ((lastErr && lastErr.message) || "unknown"));
}

function _designatedResolversForTest() { return _designatedResolvers; }

function _orderAddrs(addrs) {
  if (STATE.resultOrder === "ipv6first") {
    addrs.sort(function (a, b) { return (b.family || 0) - (a.family || 0); });
  } else if (STATE.resultOrder === "ipv4first") {
    addrs.sort(function (a, b) { return (a.family || 0) - (b.family || 0); });
  }
  return addrs;
}

async function _dualStack(queryFn, host, family) {
  if (family === 4 || family === 6) {
    return _withTimeout(queryFn(host, family), STATE.lookupTimeoutMs, host);
  }
  var first  = STATE.resultOrder === "ipv6first" ? 6 : 4;
  var second = first === 4 ? 6 : 4;
  var firstResult  = await _withTimeout(queryFn(host, first), STATE.lookupTimeoutMs, host).catch(function () { return []; });
  var secondResult = await _withTimeout(queryFn(host, second), STATE.lookupTimeoutMs, host).catch(function () { return []; });
  return (firstResult || []).concat(secondResult || []);
}

async function lookup(host, opts) {
  opts = opts || {};
  validateOpts(opts, ["family", "all"], "dns.lookup");
  var family = opts.family !== undefined ? opts.family : STATE.family;
  if (net.isIP(host)) {
    var fam = net.isIP(host);
    var literal = { address: host, family: fam };
    return opts.all ? [literal] : literal;
  }
  var cacheKey = family || 0;
  var cached = _cacheGet(host, cacheKey);
  if (cached.hit) {
    if (cached.error) throw cached.error;
    return opts.all ? cached.value : cached.value[0];
  }
  observability().safeEvent("network.dns.lookup.requested", 1, { family: cacheKey });
  var startMs = _now();
  // Resolve secure-DNS default on first use. Idempotent.
  _ensureSecureDefault();

  // Special-form hostnames per RFC 6761 (localhost / .test / .invalid /
  // .localhost) and operator-internal suffixes never hit DoH/DoT —
  // public DoH providers don't resolve these. Route through node:dns
  // (which checks /etc/hosts and the OS resolver). This keeps tests +
  // dev workflows working while public-internet resolution still goes
  // through the secure transport.
  var isLocalForm = _isLocalFormHost(host);

  try {
    var addrs;
    if (STATE.doh && !isLocalForm) {
      addrs = await _dualStack(_dohLookup, host, family);
    } else if (STATE.dot && !isLocalForm) {
      addrs = await _dualStack(_dotLookup, host, family);
    } else {
      // System resolver (operator explicit opt-out via useSystemResolver).
      var nodeOpts = { all: true };
      if (family === 4 || family === 6) nodeOpts.family = family;                // IPv4/IPv6 family literals
      addrs = await _withTimeout(dnsPromises.lookup(host, nodeOpts), STATE.lookupTimeoutMs, host);
      if (!Array.isArray(addrs)) addrs = [addrs];
    }
    var normalized = (addrs || []).map(function (a) {
      if (typeof a === "string") return { address: a, family: net.isIP(a) || 4 };
      return { address: a.address || a, family: a.family || net.isIP(a.address || a) || 4 };
    });
    _orderAddrs(normalized);
    if (normalized.length === 0) {
      throw new DnsError("dns/no-result", "dns lookup of '" + host + "' returned no addresses");
    }
    _cachePutPositive(host, cacheKey, normalized);
    observability().safeEvent("network.dns.lookup.success", 1, { latencyMs: _now() - startMs, count: normalized.length });
    return opts.all ? normalized : normalized[0];
  } catch (e) {
    _cachePutNegative(host, cacheKey, e);
    observability().safeEvent("network.dns.lookup.failure", 1, { latencyMs: _now() - startMs, code: e.code || "unknown" });
    throw e;
  }
}

async function _resolveProtocol(host, family, opts) {
  opts = opts || {};
  if (typeof host !== "string" || host.length === 0) {
    throw new DnsError("dns/bad-host", "dns.resolve" + family + ": host required");
  }
  if (net.isIP(host)) {
    if (net.isIP(host) !== family) {
      throw new DnsError("dns/wrong-family", "dns.resolve" + family + ": IP literal '" + host + "' is not family " + family);
    }
    return [host];
  }
  if (opts.transport !== undefined && opts.transport !== "doh" &&
      opts.transport !== "dot" && opts.transport !== "system") {
    throw new DnsError("dns/bad-transport",
      "dns.resolve" + family + ": transport must be 'doh' | 'dot' | 'system' | undefined");
  }
  observability().safeEvent("network.dns.resolve.requested", 1, { family: family, transport: opts.transport || "auto" });
  var startMs = _now();
  try {
    var addrs;
    var forced = opts.transport;
    if (forced === "doh" || (!forced && STATE.doh)) {
      if (!STATE.doh) {
        throw new DnsError("dns/transport-unavailable",
          "dns.resolve" + family + ": transport 'doh' requested but useDnsOverHttps() not configured");
      }
      addrs = await _withTimeout(_dohLookup(host, family), STATE.lookupTimeoutMs, host);
    } else if (forced === "dot" || (!forced && STATE.dot)) {
      if (!STATE.dot) {
        throw new DnsError("dns/transport-unavailable",
          "dns.resolve" + family + ": transport 'dot' requested but useDnsOverTls() not configured");
      }
      addrs = await _withTimeout(_dotLookup(host, family), STATE.lookupTimeoutMs, host);
    } else {
      var resolver = family === 6 ? dnsPromises.resolve6 : dnsPromises.resolve4;
      addrs = await _withTimeout(resolver(host), STATE.lookupTimeoutMs, host);
    }
    if (!Array.isArray(addrs)) addrs = [addrs];
    var normalized = addrs.map(function (a) { return typeof a === "string" ? a : (a.address || a); });
    if (normalized.length === 0) {
      throw new DnsError("dns/no-result", "dns.resolve" + family + " of '" + host + "' returned no addresses");
    }
    observability().safeEvent("network.dns.resolve.success", 1, { family: family, latencyMs: _now() - startMs, count: normalized.length });
    return normalized;
  } catch (e) {
    observability().safeEvent("network.dns.resolve.failure", 1, { family: family, latencyMs: _now() - startMs, code: e.code || "unknown" });
    if (e instanceof DnsError) throw e;
    throw new DnsError("dns/resolve-failed",
      "dns.resolve" + family + " of '" + host + "' failed: " + (e.message || String(e)));
  }
}

async function resolve4(host, opts) { return _resolveProtocol(host, 4, opts); }
async function resolve6(host, opts) { return _resolveProtocol(host, 6, opts); }
async function resolveAaaa(host, opts) { return _resolveProtocol(host, 6, opts); }

// Generic resolve API surfacing the transport opt + record type.
// `type` defaults to "A"; "AAAA" routes through resolve6; SVCB / HTTPS
// types route through the new querySvcb / queryHttps primitives.
async function resolve(host, type, opts) {
  type = (type || "A").toUpperCase();
  if (type === "A")     return _resolveProtocol(host, 4, opts);
  if (type === "AAAA")  return _resolveProtocol(host, 6, opts);
  if (type === "SVCB")  return querySvcb(host, opts);
  if (type === "HTTPS") return queryHttps(host, opts);
  throw new DnsError("dns/unsupported-type",
    "dns.resolve: type must be 'A' | 'AAAA' | 'SVCB' | 'HTTPS' (got " + JSON.stringify(type) + ")");
}

// PTR lookup — given a v4 or v6 IP literal, return the list of names
// the in-addr.arpa / ip6.arpa zones map back to. Building block for
// FCrDNS (forward-confirmed reverse DNS, RFC 8601 §3 lite) callers
// and the outbound-mail iprev surface — the PTR query plus the
// matching forward A/AAAA query share this DnsError class.
//
// dnsPromises.reverse() doesn't honor the DoH/DoT transports (those
// transports query A/AAAA/TXT via wire format; PTR queries take a
// separate code path). For now this routes through the system
// resolver — operators who require ALL DNS over secure transport
// wrap the surface with their own resolver.
async function reverse(ip) {
  if (typeof ip !== "string" || ip.length === 0) {
    throw new DnsError("dns/bad-ip", "dns.reverse: ip must be a non-empty string");
  }
  if (!net.isIP(ip)) {
    throw new DnsError("dns/bad-ip",
      "dns.reverse: '" + ip + "' is not a valid IPv4 or IPv6 address");
  }
  observability().safeEvent("network.dns.reverse.requested", 1, { family: net.isIPv6(ip) ? 6 : 4 });
  var startMs = _now();
  try {
    var ptrs = await _withTimeout(dnsPromises.reverse(ip), STATE.lookupTimeoutMs, ip);
    observability().safeEvent("network.dns.reverse.success", 1, {
      latencyMs: _now() - startMs, count: Array.isArray(ptrs) ? ptrs.length : 0,
    });
    return Array.isArray(ptrs) ? ptrs : [];
  } catch (e) {
    observability().safeEvent("network.dns.reverse.failure", 1, {
      latencyMs: _now() - startMs, code: e.code || "unknown",
    });
    if (e instanceof DnsError) throw e;
    throw new DnsError("dns/reverse-failed",
      "dns.reverse of '" + ip + "' failed: " + (e.message || String(e)));
  }
}

function nodeLookup(host, options, callback) {
  if (typeof options === "function") { callback = options; options = {}; }
  options = options || {};
  var fam = options.family !== undefined ? options.family : 0;
  lookup(host, { family: fam, all: !!options.all }).then(
    function (res) {
      if (options.all) callback(null, res);
      else callback(null, res.address, res.family);
    },
    function (err) { callback(err); }
  );
}

function _stateForTest() { return STATE; }
function _resetForTest() {
  STATE.servers = null; STATE.resultOrder = null; STATE.family = 0;
  STATE.lookupTimeoutMs = 0; STATE.cacheTtlMs = 0; STATE.cacheNegativeTtlMs = 0;
  STATE.doh = null; STATE.dot = null; STATE.systemResolver = false;
  _designatedResolvers = null;
  _clearCache();
  _resetDotPool();
}

/**
 * @primitive b.network.dns.isNullMx
 * @signature b.network.dns.isNullMx(mxRecords)
 * @since     0.8.87
 * @status    stable
 *
 * RFC 7505 Null-MX check — returns `true` when the supplied MX
 * records signal "this domain does not accept email" (a single MX
 * record with priority 0 and exchange `.`). Operators sending mail
 * call this before delivery to skip domains that have explicitly
 * opted out of email. Returns `false` for any other shape (zero
 * records, multiple records, non-zero priority, non-`.` exchange).
 *
 * MX records are expected in the `{ priority, exchange }` shape
 * returned by `node:dns.resolveMx` (or `b.network.dns.resolve(host,
 * "MX")`). Operator supplies the records; this is a pure
 * classifier, no network call.
 *
 * @example
 *   var node = require("node:dns/promises");
 *   var mx;
 *   try { mx = await node.resolveMx("example.com"); }
 *   catch (e) { mx = []; }
 *   if (b.network.dns.isNullMx(mx)) {
 *     throw new Error("example.com publishes Null-MX (RFC 7505) — does not accept email");
 *   }
 */
function isNullMx(mxRecords) {
  if (!Array.isArray(mxRecords) || mxRecords.length !== 1) return false;
  var only = mxRecords[0];
  if (!only || typeof only !== "object") return false;
  if (only.priority !== 0) return false;
  // node's resolveMx returns the exchange as "" (empty) when the
  // RDATA is "." (root); other resolvers may keep "." literal. Accept
  // both.
  return only.exchange === "" || only.exchange === ".";
}

// RFC 9905 — Deprecating DNSSEC SHA-1 Usage. The IANA DNSSEC Algorithm
// Numbers registry classifies SHA-1-based DNSKEY algorithms (5
// RSASHA1, 7 RSASHA1-NSEC3-SHA1, 10 RSASHA512-using-SHA1-NSEC3) and
// SHA-1 DS digest type 1 as "MUST NOT be used" / "MUST NOT be
// supported". Operators auditing inbound DNSSEC chain-of-trust data
// classify a record's algorithm number to decide whether to refuse
// the validation as deprecated.
//
// Returns the classification verdict object:
//   {
//     deprecated:  boolean,  // true when SHA-1 family per RFC 9905 §3-§4
//     algorithm:   number,   // echo of input
//     name:        string,   // human-readable label
//     reason:      string,   // citation
//   }
// for any IANA DNSKEY algorithm number, or null for unknown / non-
// numeric input. Defensive request-shape reader — never throws.

/**
 * @primitive b.network.dns.classifyDnskeyAlgorithm
 * @signature b.network.dns.classifyDnskeyAlgorithm(algorithm)
 * @since     0.8.91
 * @status    stable
 * @related   b.network.dns.classifyDsDigestType, b.network.dns.isNullMx
 *
 * Classify a DNSKEY / RRSIG algorithm number against the IANA DNS
 * Security Algorithm Numbers registry, flagging SHA-1-based and
 * other deprecated algorithms per RFC 9905 (Deprecating DNSSEC
 * SHA-1 Usage), RFC 8624 (Algorithm Implementation Requirements),
 * and RFC 6944 / RFC 6725 (RSAMD5 deprecation).
 *
 * Returns `{ algorithm, name, deprecated, reason, known }` for any
 * IANA-assigned number; `known: false` for unassigned numbers
 * (operators decide whether unassigned == deprecated for their
 * threat model). Returns `null` for non-integer / non-finite input.
 *
 * Operators auditing inbound DNSSEC chain-of-trust evidence call
 * this on each link's algorithm number and refuse the validation
 * when `deprecated === true`. Defensive request-shape reader —
 * never throws.
 *
 * @example
 *   var v = b.network.dns.classifyDnskeyAlgorithm(5);
 *   // → { algorithm: 5, name: "RSASHA1", deprecated: true,
 *   //     reason: "SHA-1 deprecated (RFC 9905 §3)", known: true }
 *   if (v && v.deprecated) throw new Error("refuse DNSSEC algo " + v.name);
 *
 *   b.network.dns.classifyDnskeyAlgorithm(13);
 *   // → { algorithm: 13, name: "ECDSAP256SHA256", deprecated: false, ... }
 */

// Canonical DNSKEY algorithm vocabulary (IANA DNS Security Algorithm
// Numbers registry — https://www.iana.org/assignments/dns-sec-alg-numbers).
// Operators looking up the human-readable label or computing whether
// the framework's own DNSSEC paths use a deprecated algorithm walk
// this table. Every IANA-assigned number gets an entry (including
// Reserved / Private-use values) so `classifyDnskeyAlgorithm()`
// returns `known: true` for the full assigned space; the "Unassigned"
// range (17-122, 124-251) is the only set that surfaces as
// `known: false`. Marked-deprecated entries cite the controlling
// RFC; Reserved / Private-use entries are flagged so operators
// auditing DNSSEC chain-of-trust evidence know they cannot validate
// the entry against a public algorithm registry.
var DNSKEY_ALGORITHMS = Object.freeze({
  1:   { name: "RSAMD5",             deprecated: true,  reason: "MD5 broken (RFC 6944 §2.1, RFC 6725)" },
  2:   { name: "DH",                 deprecated: true,  reason: "Diffie-Hellman key (RFC 2539) — never widely deployed; superseded by signature algorithms" },
  3:   { name: "DSA",                deprecated: true,  reason: "DSA deprecated (RFC 8624 §3.1)" },
  4:   { name: "Reserved",           deprecated: true,  reason: "Reserved (RFC 4034 §A.1) — not for production use" },
  5:   { name: "RSASHA1",            deprecated: true,  reason: "SHA-1 deprecated (RFC 9905 §3)" },
  6:   { name: "DSA-NSEC3-SHA1",     deprecated: true,  reason: "SHA-1 deprecated (RFC 9905 §3); DSA deprecated (RFC 8624 §3.1)" },
  7:   { name: "RSASHA1-NSEC3-SHA1", deprecated: true,  reason: "SHA-1 deprecated (RFC 9905 §3)" },
  8:   { name: "RSASHA256",          deprecated: false, reason: "current — RFC 5702" },                                  // IANA DNSKEY algorithm number
  9:   { name: "Reserved",           deprecated: true,  reason: "Reserved (RFC 5155) — not for production use" },
  10:  { name: "RSASHA512",          deprecated: false, reason: "current — RFC 5702" },
  11:  { name: "Reserved",           deprecated: true,  reason: "Reserved (RFC 5155) — not for production use" },
  12:  { name: "ECC-GOST",           deprecated: true,  reason: "deprecated (RFC 8624 §3.1)" },
  13:  { name: "ECDSAP256SHA256",    deprecated: false, reason: "current — RFC 6605" },
  14:  { name: "ECDSAP384SHA384",    deprecated: false, reason: "current — RFC 6605" },
  15:  { name: "ED25519",            deprecated: false, reason: "current — RFC 8080" },
  16:  { name: "ED448",              deprecated: false, reason: "current — RFC 8080" },                                  // IANA DNSKEY algorithm number
  // 17-122: Unassigned per IANA. Operators that see one of these
  // get known: false from classifyDnskeyAlgorithm() — the entry
  // is not a typo against the framework table, it's a value the
  // registry hasn't allocated yet.
  // 123-251: Reserved per IANA.
  252: { name: "INDIRECT",           deprecated: true,  reason: "Reserved indirect-keys placeholder (RFC 4034 §A.1) — not usable for signing/verification" },                                      // IANA DNSKEY algorithm number
  253: { name: "PRIVATEDNS",         deprecated: false, reason: "Private algorithm identified by domain name (RFC 4034 §A.1.1) — operators using this assume the private algorithm itself is acceptable" },
  254: { name: "PRIVATEOID",         deprecated: false, reason: "Private algorithm identified by OID (RFC 4034 §A.1.2) — operators using this assume the private algorithm itself is acceptable" },
  255: { name: "Reserved",           deprecated: true,  reason: "Reserved (RFC 4034 §A.1) — not for production use" },
});

/**
 * @primitive b.network.dns.classifyDsDigestType
 * @signature b.network.dns.classifyDsDigestType(digestType)
 * @since     0.8.91
 * @status    stable
 * @related   b.network.dns.classifyDnskeyAlgorithm, b.network.dns.isNullMx
 *
 * Classify a DS-record digest type against the IANA DNSSEC Delegation
 * Signer (DS) Resource Record (RR) Type Digest Algorithms registry,
 * flagging SHA-1 (digest type 1) as deprecated per RFC 9905 §4.
 *
 * Returns `{ digestType, name, deprecated, reason, known }` for any
 * IANA-assigned number; `null` for non-integer input.
 *
 * @example
 *   var v = b.network.dns.classifyDsDigestType(1);
 *   // → { digestType: 1, name: "SHA-1", deprecated: true,
 *   //     reason: "SHA-1 deprecated (RFC 9905 §4)", known: true }
 *
 *   b.network.dns.classifyDsDigestType(2);
 *   // → { digestType: 2, name: "SHA-256", deprecated: false, ... }
 */

// DS digest-type vocabulary (RFC 4034 §5.1 + RFC 6605 §6 + RFC 8624
// §3.2 + RFC 9558). Digest type 1 = SHA-1 is deprecated per RFC 9905
// §4. Digest types 5 (GOST R 34.11-2012) and 6 (SM3) added by RFC
// 9558. Reserved value 0 surfaced for completeness.
var DS_DIGEST_TYPES = Object.freeze({
  0: { name: "Reserved",            deprecated: true,  reason: "Reserved (RFC 3658) — not for production use" },
  1: { name: "SHA-1",               deprecated: true,  reason: "SHA-1 deprecated (RFC 9905 §4)" },
  2: { name: "SHA-256",             deprecated: false, reason: "current — RFC 4509" },
  3: { name: "GOST R 34.11-94",     deprecated: true,  reason: "deprecated (RFC 8624 §3.2; superseded by GOST 2012 in RFC 9558)" },
  4: { name: "SHA-384",             deprecated: false, reason: "current — RFC 6605 §6" },
  5: { name: "GOST R 34.11-2012",   deprecated: false, reason: "current — RFC 9558 §3" },
  6: { name: "SM3",                 deprecated: false, reason: "current — RFC 9558 §3 (Chinese national standard)" },
});

function classifyDnskeyAlgorithm(algorithm) {
  if (typeof algorithm !== "number" || !isFinite(algorithm) || Math.floor(algorithm) !== algorithm) {
    return null;
  }
  var row = DNSKEY_ALGORITHMS[algorithm];
  if (!row) {
    return {
      algorithm:  algorithm,
      name:       "unassigned",
      deprecated: false,
      reason:     "no IANA assignment for algorithm " + algorithm,
      known:      false,
    };
  }
  return {
    algorithm:  algorithm,
    name:       row.name,
    deprecated: row.deprecated,
    reason:     row.reason,
    known:      true,
  };
}

function classifyDsDigestType(digestType) {
  if (typeof digestType !== "number" || !isFinite(digestType) || Math.floor(digestType) !== digestType) {
    return null;
  }
  var row = DS_DIGEST_TYPES[digestType];
  if (!row) {
    return {
      digestType: digestType,
      name:       "unassigned",
      deprecated: false,
      reason:     "no IANA assignment for digest type " + digestType,
      known:      false,
    };
  }
  return {
    digestType: digestType,
    name:       row.name,
    deprecated: row.deprecated,
    reason:     row.reason,
    known:      true,
  };
}

module.exports = {
  setServers:                  setServers,
  isNullMx:                    isNullMx,
  classifyDnskeyAlgorithm:     classifyDnskeyAlgorithm,
  classifyDsDigestType:        classifyDsDigestType,
  DNSKEY_ALGORITHMS:           DNSKEY_ALGORITHMS,
  DS_DIGEST_TYPES:             DS_DIGEST_TYPES,
  getServers:                  getServers,
  setResultOrder:              setResultOrder,
  setFamily:                   setFamily,
  setLookupTimeoutMs:          setLookupTimeoutMs,
  setCacheTtlMs:               setCacheTtlMs,
  useDnsOverHttps:             useDnsOverHttps,
  useDnsOverTls:               useDnsOverTls,
  useSystemResolver:           useSystemResolver,
  useDesignatedResolvers:      useDesignatedResolvers,
  discoverEncrypted:           discoverEncrypted,
  lookup:                      lookup,
  resolve:                     resolve,
  resolve4:                    resolve4,
  resolve6:                    resolve6,
  resolveAaaa:                 resolveAaaa,
  resolveSecure:               resolveSecure,
  reverse:                     reverse,
  querySvcb:                   querySvcb,
  queryHttps:                  queryHttps,
  nodeLookup:                  nodeLookup,
  clearCache:                  _clearCache,
  DnsError:                    DnsError,
  _parseSvcbRdata:             _parseSvcbRdata,
  _decodeDnsAnswerRaw:         _decodeDnsAnswerRaw,
  _readDnsName:                _readDnsName,
  _stateForTest:               _stateForTest,
  _resetForTest:               _resetForTest,
  _designatedResolversForTest: _designatedResolversForTest,
};

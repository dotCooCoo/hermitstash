"use strict";
/**
 * @module     b.network.dns.resolver
 * @nav        Network
 * @title      DNS Resolver
 * @order      215
 *
 * @intro
 *   Validating stub resolver that composes `b.network.dns` transport
 *   (DoT / DoH / system) with `b.safeDns` parsing and a TTL-aware
 *   cache. Used by every framework consumer that walks the DNS:
 *   DKIM TXT lookup, MTA-STS verify, DANE TLSA fetch, BIMI / VMC
 *   discovery, SVCB / HTTPS discovery, RBL queries, AutoConfig /
 *   AutoDiscover endpoint resolution, future MX lookup at submission.
 *
 *   Stub-mode resolver — every query goes to the operator-configured
 *   upstream recursive resolver (default `cloudflare-dns.com` over
 *   DoH per `b.network.dns.useDnsOverHttps()`). DNSSEC validation is
 *   delegated to the upstream resolver and surfaced via the AD bit
 *   (RFC 4035 §3.2.3); per-call `validate: true` opt-in re-checks
 *   the AD bit per-query, refusing responses with `AD=0`. Full local
 *   RRSIG signature verification is deferred — it requires IANA root
 *   trust anchor distribution + management which has its own lifecycle
 *   (root KSK rollover, RFC 5011) that doesn't belong in a stub. An
 *   operator that needs local RRSIG verify points the resolver at
 *   their own validating recursive (Unbound / BIND9) and the AD bit
 *   surfaces here; alternatively, `b.safeDns.parseResponse` exposes
 *   the parsed DNSKEY + RRSIG + DS records for an operator-supplied
 *   verifier.
 *
 *   QNAME minimization (RFC 9156) is a recursive-resolver concern —
 *   the framework runs in stub mode so the operator's upstream
 *   recursive (Cloudflare / Google / Unbound) implements QNAME-min;
 *   our queries always carry the full QNAME and there's nothing to
 *   minimize. Documented so operators don't pass `qnameMin: true` and
 *   expect a behavior change.
 *
 *   ## TTL cache + serve-stale (RFC 8767)
 *
 *   Every successful response caches by `{ name, type }` keyed on the
 *   minimum TTL across the answer RRs (RFC 2181 §5.2 — RRset TTL is
 *   the minimum of the included RR TTLs). On expiry the entry is
 *   removed from the live cache; with `serveStale: <ms>` configured,
 *   expired entries are retained for that additional window and
 *   returned on upstream failure or malformed response (RFC 8767 —
 *   stale-bread-is-better-than-no-bread for resolver resiliency
 *   under DoS / authoritative outage). Returned entries carry
 *   `{ stale: true }` so consumer code can decide whether to use the
 *   data or hard-fail. RFC 8767 §6 recommends a 7-day max stale
 *   window; we default to 6h.
 *
 *   ## CNAME chain following (RFC 1912 §2.4)
 *
 *   `followCnames(name, type)` walks CNAME redirections until the
 *   target record arrives or the chain depth cap from `b.safeDns`
 *   trips. Each hop is its own resolver query; each hop's response
 *   parses through `b.safeDns.parseResponse` independently. Default
 *   cap = 8 (matches BIND9's canonical-name-translation cap). RFC
 *   1912 §2.4 warns against long CNAME chains; the cap defends
 *   redirect-loop DoS regardless of upstream resolver behavior.
 *
 *   ## CVE / threat-model coverage
 *
 *   The resolver layer's defenses (parser-level + cache-level —
 *   transport-level defenses live in `b.network.dns`):
 *
 *     - Cache-poisoning resilience: every parse routes through
 *       `b.safeDns` which caps response bytes, RR counts, name
 *       lengths, and pointer-chain depth — bounds the attacker's
 *       inflation surface for poisoning attempts (CVE-2008-1447
 *       Kaminsky class; the random query ID + TLS-encrypted DoH
 *       transport defend transport-side, this layer defends parse-
 *       side).
 *     - CVE-2022-3204 (NRDelegationAttack): per-section RR caps in
 *       `b.safeDns` bound the authority + additional sections that
 *       back a malicious non-responsive delegation.
 *     - CVE-2023-50387 (KeyTrap) + CVE-2023-50868 (NSEC3-encloser):
 *       DNSKEY + RRSIG + NSEC3 record counts bounded at parse time;
 *       validators downstream don't see the inflated set.
 *     - CVE-2024-1737 (BIND9 large-RRset exhaustion): RR-count caps
 *       refuse responses with abnormally large RRsets per hostname.
 *     - CNAME redirect loops: `safeDns.checkCnameChainDepth` at every
 *       hop in `followCnames`; matches BIND9's operational cap of 8.
 *     - TTL pinning of poisoned entries: operator-configurable
 *       `maxTtlMs` ceiling (default 24h) caps any TTL the upstream
 *       returns; a 2^31-second TTL (RFC 2181 absolute max) can't
 *       persist past the ceiling.
 *
 *   ## Why it exists
 *
 *   `node:dns` returns parsed values but doesn't bound any of the
 *   dimensions an attacker can inflate — RR count, CNAME depth,
 *   compression-pointer chain, TXT rdata length. The validating
 *   resolver routes every parse through `b.safeDns` and exposes one
 *   shape every framework consumer can compose, replacing the
 *   scattered `node:dns` reach-throughs across `lib/mail-*.js`,
 *   `lib/mtla-sts*.js`, `lib/dane*.js`, and future MX / BIMI / SVCB
 *   primitives. Audit + posture rides through the resolver instance.
 *
 * @card
 *   Validating stub resolver — composes b.network.dns transport,
 *   b.safeDns parsing, TTL-aware cache with serve-stale on failure
 *   (RFC 8767), CNAME chain following with safeDns depth cap, DNSSEC
 *   AD-bit surface (RFC 4035 §3.2.3).
 */

var C                  = require("./constants");
var https              = require("node:https");
var bCrypto            = require("./crypto");
var { defineClass }    = require("./framework-error");
var networkDns         = require("./network-dns");
var safeDns            = require("./safe-dns");
var safeUrl            = require("./safe-url");
var safeBuffer         = require("./safe-buffer");
var lazyRequire        = require("./lazy-require");

var audit              = lazyRequire(function () { return require("./audit"); });

var ResolverError = defineClass("ResolverError", { alwaysPermanent: true });

// Default cache TTL ceiling — RFC 1035 §3.2.1 allows TTLs up to 2^31
// seconds but real-world records cap much lower. We cap operator-side
// to 24h so a long-TTL response can't pin a stale value past a working
// day. Refresh on next query.
var DEFAULT_MAX_TTL_MS    = C.TIME.hours(24);
var DEFAULT_MIN_TTL_MS    = C.TIME.seconds(60);
var DEFAULT_STALE_WINDOW  = C.TIME.hours(6);
var DEFAULT_PROFILE       = "strict";
// BUG-1 / MAIL-26 — CWE-400/770. Bound the cache so a hostile peer
// that can drive query-name selection (e.g. inbound SMTP forwarding
// DKIM `s=` / `d=` tag-controlled lookups) cannot inflate the Map to
// OOM. Default 5000 entries: a parsed-response object ~100 bytes ×
// 5000 ≈ 500 KiB, several orders below operator-relevant memory
// pressure. LRU eviction picks the oldest accessed entry on overflow.
var DEFAULT_MAX_CACHE_ENTRIES = 5000;                                                                  // allow:raw-byte-literal — cache-entry count, not a byte/time value

var QTYPE_BY_NAME = Object.freeze({
  A:      1,
  NS:     2,
  CNAME:  5,                                                                                            // allow:raw-byte-literal — IANA DNS qtype code
  SOA:    6,                                                                                            // allow:raw-byte-literal — IANA DNS qtype code
  PTR:    12,                                                                                           // allow:raw-byte-literal — IANA DNS qtype code
  MX:     15,                                                                                           // allow:raw-byte-literal — IANA DNS qtype code
  TXT:    16,                                                                                           // allow:raw-byte-literal — IANA DNS qtype code
  AAAA:   28,                                                                                           // allow:raw-byte-literal — IANA DNS qtype code
  SRV:    33,                                                                                           // allow:raw-byte-literal — IANA DNS qtype code
  DS:     43,                                                                                           // allow:raw-byte-literal — IANA DNS qtype code
  DNSKEY: 48,                                                                                           // allow:raw-byte-literal — IANA DNS qtype code
  TLSA:   52,                                                                                           // allow:raw-byte-literal — IANA DNS qtype code
  SVCB:   64,                                                                                           // allow:raw-byte-literal — IANA DNS qtype code
  HTTPS:  65,                                                                                           // allow:raw-byte-literal — IANA DNS qtype code
});

/**
 * @primitive b.network.dns.resolver.create
 * @signature b.network.dns.resolver.create(opts?)
 * @since     0.9.31
 * @status    stable
 * @related   b.safeDns.parseResponse, b.network.dns.querySvcb
 *
 * Build a resolver instance with the given options. Returns an
 * instance with `.query(name, type, opts) → Promise<{ rrs, ttl,
 * fromCache, stale, validated, response }>` plus per-type shortcuts.
 *
 * @opts
 *   profile:     "strict" | "balanced" | "permissive",
 *   posture:     "hipaa" | "pci-dss" | "gdpr" | "soc2",
 *   maxTtlMs:    number,           // cap any TTL from upstream; default 24h
 *   minTtlMs:    number,           // floor short-TTL records; default 60s
 *   serveStale:  number | false,   // ms to retain expired entries; default 6h
 *   transport:   { lookup(name, qtype) → Promise<Buffer> },   // operator override
 *   audit:       b.audit namespace,
 *
 * @example
 *   var resolver = b.network.dns.resolver.create({ profile: "strict" });
 *   var r = await resolver.queryTxt("_dmarc.example.com");
 *   console.log(r.rrs.map(function (rr) { return rr.decoded.join(""); }));
 */
function create(opts) {
  opts = opts || {};
  var profile     = opts.profile || (opts.posture && safeDns.compliancePosture(opts.posture)) || DEFAULT_PROFILE;
  if (!safeDns.PROFILES[profile]) {
    throw new ResolverError("resolver/bad-profile",
      "create: unknown profile '" + profile + "'");
  }
  var maxTtlMs    = typeof opts.maxTtlMs === "number" ? opts.maxTtlMs : DEFAULT_MAX_TTL_MS;
  var minTtlMs    = typeof opts.minTtlMs === "number" ? opts.minTtlMs : DEFAULT_MIN_TTL_MS;
  var serveStale  = opts.serveStale === false ? 0 :
                    typeof opts.serveStale === "number" ? opts.serveStale : DEFAULT_STALE_WINDOW;
  var transport   = opts.transport || _defaultTransport();
  var auditImpl   = opts.audit || audit();

  if (typeof transport.lookup !== "function") {
    throw new ResolverError("resolver/bad-transport",
      "create: transport.lookup must be a function");
  }
  if (!isFinite(maxTtlMs) || maxTtlMs <= 0) {
    throw new ResolverError("resolver/bad-input",
      "create: maxTtlMs must be a positive finite number");
  }
  if (!isFinite(minTtlMs) || minTtlMs < 0) {
    throw new ResolverError("resolver/bad-input",
      "create: minTtlMs must be a non-negative finite number");
  }
  if (!isFinite(serveStale) || serveStale < 0) {
    throw new ResolverError("resolver/bad-input",
      "create: serveStale must be a non-negative finite number or false");
  }
  var maxCacheEntries = typeof opts.maxCacheEntries === "number"
    ? opts.maxCacheEntries : DEFAULT_MAX_CACHE_ENTRIES;
  if (!isFinite(maxCacheEntries) || maxCacheEntries < 1 ||
      Math.floor(maxCacheEntries) !== maxCacheEntries) {
    throw new ResolverError("resolver/bad-input",
      "create: maxCacheEntries must be a positive integer");
  }

  var cache = new Map();                  // key → { response, parsed, ttl, expiresAt, staleUntil }

  // CWE-400/770 / BUG-1 — LRU eviction on insert when the cache is at
  // capacity. v8 Map preserves insertion order; oldest key is the
  // first entry returned by Map.keys().next().
  function _evictIfFull() {
    while (cache.size >= maxCacheEntries) {
      var oldest = cache.keys().next();
      if (oldest.done) break;
      cache.delete(oldest.value);
    }
  }
  // Touching a hit moves it to the LRU tail — delete-then-set keeps
  // active queries hot under cache pressure.
  function _touch(key, entry) {
    cache.delete(key);
    cache.set(key, entry);
  }

  function _key(name, qtype) {
    return name.toLowerCase() + "|" + qtype;
  }

  function _safeEmit(action, metadata) {
    try {
      if (auditImpl && typeof auditImpl.safeEmit === "function") {
        auditImpl.safeEmit({ action: "network.dns.resolver." + action, outcome: "success", metadata: metadata });
      }
    } catch (_e) { /* audit drop-silent per validation tier policy */ }
  }

  async function query(name, type, qopts) {
    qopts = qopts || {};
    if (typeof name !== "string" || name.length === 0) {
      throw new ResolverError("resolver/bad-input",
        "query: name must be a non-empty string");
    }
    var qtype = typeof type === "number" ? type :
                typeof type === "string" ? QTYPE_BY_NAME[type.toUpperCase()] :
                null;
    if (!qtype) {
      throw new ResolverError("resolver/bad-input",
        "query: unknown qtype '" + type + "'");
    }
    var validate = qopts.validate === true;
    var key = _key(name, qtype);

    // Cache hit fresh?
    var now = Date.now();
    var hit = cache.get(key);
    if (hit && hit.expiresAt > now) {
      // validate: true refuses cached responses that weren't AD=1 when
      // first cached — a non-validating call mustn't poison a later
      // validating call's verdict. RFC 4035 §3.2.3: AD is per-response,
      // not per-record, so we honor the original verdict on every hit.
      if (validate && !hit.validated) {
        throw new ResolverError("resolver/validate-failed",
          "query: validate: true but cached response was AD=0 for " +
          name + "/" + qtype);
      }
      _touch(key, hit);                     // LRU bump
      return _result(hit.parsed, hit.ttl, true, false, hit.validated);
    }

    // Cache miss / expired — fetch from upstream.
    var wireResponse;
    try {
      wireResponse = await transport.lookup(name, qtype);
    } catch (e) {
      // Upstream failure — serve stale if we have it within window.
      if (hit && serveStale > 0 && hit.staleUntil > now) {
        _safeEmit("served_stale", { name: name, qtype: qtype, reason: "upstream-failure" });
        return _result(hit.parsed, hit.ttl, true, true, hit.validated);
      }
      throw new ResolverError("resolver/upstream-failed",
        "query: upstream lookup failed for " + name + "/" + qtype + ": " + (e && e.message || String(e)));
    }

    var parsed;
    try {
      parsed = safeDns.parseResponse(wireResponse, { profile: profile });
    } catch (e) {
      // Malformed upstream response — serve stale if within window.
      if (hit && serveStale > 0 && hit.staleUntil > now) {
        _safeEmit("served_stale", { name: name, qtype: qtype, reason: "parse-failed" });
        return _result(hit.parsed, hit.ttl, true, true, hit.validated);
      }
      throw e;
    }

    if (parsed.rcode !== 0) {
      // RFC 1035 §4.1.1 — non-zero RCODE. Surface and refuse caching.
      throw new ResolverError("resolver/nxdomain-or-error",
        "query: upstream RCODE=" + parsed.rcode + " for " + name + "/" + qtype);
    }

    // AD bit (RFC 4035 §3.2.3) — set by upstream after chain validation.
    // Bit 5 of byte 3 of header; parsed.flags is the full 16-bit flags
    // field at offset 2..3. AD is bit 5 within byte 3 = bit 5 of the
    // low byte of the 16-bit flags value.
    var ad = (parsed.flags & 0x0020) !== 0;                                                              // allow:raw-byte-literal — RFC 4035 §3.2.3 AD-bit mask within DNS header flags
    if (validate && !ad) {
      throw new ResolverError("resolver/validate-failed",
        "query: validate: true but upstream returned AD=0 for " + name + "/" + qtype);
    }

    // Compute effective TTL — min across answer RRs (RFC 2181 §5.2:
    // RRset TTL is the minimum of the included RR TTLs), then clamped
    // to [minTtlMs, maxTtlMs] to bound any single RR's TTL from
    // pinning a poisoned entry past operator policy.
    var rrTtl = _minTtl(parsed.answer);
    var ttlMs = Math.max(minTtlMs, Math.min(maxTtlMs, rrTtl * C.TIME.seconds(1)));
    var expiresAt  = now + ttlMs;
    var staleUntil = serveStale > 0 ? expiresAt + serveStale : expiresAt;
    _evictIfFull();
    cache.set(key, {
      parsed:     parsed,
      ttl:        ttlMs,
      expiresAt:  expiresAt,
      staleUntil: staleUntil,
      validated:  ad,
    });
    _safeEmit("cached", { name: name, qtype: qtype, ttlMs: ttlMs, adBit: ad });
    return _result(parsed, ttlMs, false, false, ad);
  }

  function _result(parsed, ttlMs, fromCache, stale, validated) {
    return {
      rrs:       parsed.answer,
      authority: parsed.authority,
      additional: parsed.additional,
      ttl:       ttlMs,
      fromCache: fromCache,
      stale:     stale,
      validated: validated,
      response:  parsed,
    };
  }

  /**
   * @primitive b.network.dns.resolver.followCnames
   * @signature b.network.dns.resolver.followCnames(name, type, opts?)
   * @since     0.9.31
   * @status    stable
   *
   * Walk CNAME redirections until the target record arrives or the
   * chain depth cap from `b.safeDns` trips. Returns the same shape as
   * `query()` plus `chain: [name, name, ...]` listing each hop.
   *
   * @opts
   *   validate:  boolean,   // per-call: refuse if upstream AD=0
   *
   * @example
   *   var r = await resolver.followCnames("alias.example.com", "A");
   *   console.log(r.chain, r.rrs.map(function (rr) { return rr.decoded; }));
   */
  async function followCnames(name, type, qopts) {
    var depth = 0;
    var chain = [name];
    var current = name;
    while (true) {
      safeDns.checkCnameChainDepth(depth, { profile: profile });
      var r = await query(current, type, qopts);
      // If any RR matches the target type, we're done.
      var typeCode = typeof type === "number" ? type : QTYPE_BY_NAME[type.toUpperCase()];
      var hasTarget = r.rrs.some(function (rr) { return rr.type === typeCode; });
      if (hasTarget) {
        r.chain = chain;
        return r;
      }
      // Otherwise look for a CNAME to follow.
      var cnameRr = r.rrs.find(function (rr) { return rr.type === QTYPE_BY_NAME.CNAME; });
      if (!cnameRr) {
        // No matching type and no CNAME — return empty result.
        r.chain = chain;
        return r;
      }
      depth += 1;
      current = cnameRr.decoded;
      chain.push(current);
    }
  }

  function _typed(typeName) {
    return function (name, qopts) { return query(name, typeName, qopts); };
  }

  function clearCache() { cache.clear(); }

  function cacheSize()  { return cache.size; }

  return {
    query:        query,
    followCnames: followCnames,
    queryA:       _typed("A"),
    queryAaaa:    _typed("AAAA"),
    queryCname:   _typed("CNAME"),
    queryMx:      _typed("MX"),
    queryNs:      _typed("NS"),
    queryTxt:     _typed("TXT"),
    querySrv:     _typed("SRV"),
    queryTlsa:    _typed("TLSA"),
    queryDs:      _typed("DS"),
    queryDnskey:  _typed("DNSKEY"),
    querySvcb:    _typed("SVCB"),
    queryHttps:   _typed("HTTPS"),
    clearCache:   clearCache,
    cacheSize:    cacheSize,
    profile:      profile,
    ResolverError: ResolverError,
  };
}

function _defaultTransport() {
  // Default transport — compose b.network.dns.useDnsOverHttps()'s
  // existing DoH path. We use the wire-format DoH endpoint directly
  // so the response arrives as raw bytes for safeDns parsing.
  return {
    lookup: function (name, qtype) {
      return _wireLookup(name, qtype);
    },
  };
}

// _wireLookup — fetch a wire-format DNS response via the framework's
// existing DoH path. Returns the raw response bytes for safeDns to
// parse. Distinct from the existing network-dns DoH path which returns
// already-decoded address strings — we need the raw bytes here.
async function _wireLookup(name, qtype) {
  var url = networkDns._getDohUrlForTest ? networkDns._getDohUrlForTest() : "https://cloudflare-dns.com/dns-query";
  // Encode a wire-format query for the target qtype.
  var qbuf = _encodeWireQuery(name, qtype);
  var b64 = bCrypto.toBase64Url(qbuf);
  var getUrl = url + (url.indexOf("?") === -1 ? "?" : "&") + "dns=" + b64;
  var u = safeUrl.parse(getUrl, { allowedProtocols: safeUrl.ALLOW_HTTP_TLS });
  return new Promise(function (resolve, reject) {
    // Raw DoH wire-format request — bypasses b.httpClient envelope
    // because we need the raw binary response bytes for safeDns to
    // parse (httpClient assumes JSON/text shapes).
    var req = https.request({                                                                            // allow:raw-outbound-http — DoH wire-format response bytes; b.httpClient envelopes assume text/JSON, and httpClient → ssrfGuard → DNS → DoH would form a cycle
      hostname:   u.hostname,
      port:       u.port || 443,                                                                        // allow:raw-byte-literal — HTTPS port
      path:       u.pathname + u.search,
      method:     "GET",
      headers:    { "accept": "application/dns-message" },
      minVersion: "TLSv1.3",
      ecdhCurve:  C.TLS_GROUP_CURVE_STR,
    }, function (res) {
      var collector = safeBuffer.boundedChunkCollector({
        maxBytes:    C.BYTES.kib(64),
        errorClass:  ResolverError,
        sizeCode:    "resolver/upstream-too-large",
        sizeMessage: "DoH response exceeds 64 KiB",
      });
      var pushFailed = null;
      res.on("data", function (c) { if (!pushFailed) { try { collector.push(c); } catch (e) { pushFailed = e; } } });
      res.on("end", function () {
        try {
          if (pushFailed) { reject(pushFailed); return; }
          if (res.statusCode !== 200) {                                                                  // allow:raw-byte-literal — HTTP 200 OK
            reject(new ResolverError("resolver/upstream-http",
              "DoH HTTP " + res.statusCode + " for " + name));
            return;
          }
          resolve(collector.result());
        } catch (e) { reject(e); }
      });
    });
    req.on("error", function (e) {
      reject(new ResolverError("resolver/upstream-failed",
        "DoH request failed: " + e.message));
    });
    req.end();
  });
}

// _encodeWireQuery — assemble a wire-format DNS query for (name, qtype).
// Mirrors the encoder in network-dns.js but accepts an explicit qtype
// (the existing function hardcodes A/AAAA based on family).
function _encodeWireQuery(name, qtype) {
  var parts = name.split(".").filter(Boolean);
  var nameLen = 1;
  for (var i = 0; i < parts.length; i += 1) nameLen += 1 + Buffer.byteLength(parts[i], "ascii");
  var buf = Buffer.alloc(12 + nameLen + 4);                                                              // allow:raw-byte-literal — RFC 1035 §4.1.1 header (12) + question tail (4) + name
  var id = bCrypto.randomInt(0, 0x10000);                                                              // allow:raw-byte-literal — RFC 1035 §4.1.1 16-bit query ID space
  buf.writeUInt16BE(id, 0);
  buf.writeUInt16BE(0x0100, 2);                                                                          // allow:raw-byte-literal — RFC 1035 §4.1.1 RD=1 flags
  buf.writeUInt16BE(1, 4);                                                                               // allow:raw-byte-literal — RFC 1035 §4.1.1 qdcount
  var off = 12;                                                                                          // allow:raw-byte-literal — RFC 1035 §4.1.1 header end / question start
  for (var p = 0; p < parts.length; p += 1) {
    var s = parts[p];
    buf.writeUInt8(Buffer.byteLength(s, "ascii"), off);
    off += 1;
    off += buf.write(s, off, "ascii");
  }
  buf.writeUInt8(0, off);
  off += 1;
  buf.writeUInt16BE(qtype, off);
  off += 2;                                                                                              // allow:raw-byte-literal — RFC 1035 §4.1.2 QTYPE width
  buf.writeUInt16BE(1, off);                                                                             // allow:raw-byte-literal — RFC 1035 §4.1.2 QCLASS=IN
  return buf;
}

function _minTtl(rrs) {
  if (!rrs || rrs.length === 0) return 0;
  var min = Infinity;
  for (var i = 0; i < rrs.length; i += 1) {
    if (rrs[i].ttl < min) min = rrs[i].ttl;
  }
  return min === Infinity ? 0 : min;
}

module.exports = {
  create:         create,
  ResolverError:  ResolverError,
  QTYPE_BY_NAME:  QTYPE_BY_NAME,
};

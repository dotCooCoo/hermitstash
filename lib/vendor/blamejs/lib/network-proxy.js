"use strict";

var http = require("node:http");
var https = require("node:https");
var net = require("node:net");
var nodeTls = require("node:tls");

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeUrl = require("./safe-url");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var ProxyError = defineClass("ProxyError", { alwaysPermanent: false });

// Protocol-fixed byte counts — passthrough through C.BYTES so the codebase
// has a single source of truth for "what shape is this number".
var IPV4_PREFIX_MAX_BITS = C.BYTES.bytes(32);   // RFC 791 §3.1 IPv4 address bit-width
var DEFAULT_HTTPS_PORT   = 443;                 // RFC 9110 §4.2.2
var DEFAULT_HTTP_PORT    = C.BYTES.bytes(80);   // RFC 9110 §4.2.1

var observability = lazyRequire(function () { return require("./observability"); });
// Lazy so pqc-agent's TLS/audit graph isn't pulled into every process that
// imports network-proxy but never proxies an https upstream. Used only to audit
// a classical-group fallback on a proxy-tunneled TLS handshake (the direct path
// audits in pqc-agent.create()).
var pqcAgent = lazyRequire(function () { return require("./pqc-agent"); });

var STATE = {
  http:    null,
  https:   null,
  noProxy: [],
  auth:    null,
  agentCache: new Map(),
};

function _parseAuth(spec) {
  if (!spec) return null;
  var idx = spec.indexOf(":");
  if (idx === -1) return null;
  return { user: spec.slice(0, idx), pass: spec.slice(idx + 1) };
}

function _parseProxyUrl(value) {
  if (!value) return null;
  try {
    return safeUrl.parse(value, {
      allowedProtocols: safeUrl.ALLOW_HTTP_ALL,
      allowUserinfo:    true,   // proxy auth is conventionally placed in the URL
      errorClass:       ProxyError,
    });
  } catch (e) {
    if (e && e.isSafeUrlError && e.code === "safe-url/protocol-disallowed") {
      throw new ProxyError("proxy/bad-protocol", "proxy URL must be http:// or https://, got " + value);
    }
    throw new ProxyError("proxy/bad-url", "invalid proxy URL: " + value);
  }
}

function _parseNoProxy(spec) {
  if (!spec) return [];
  return String(spec).split(",").map(function (s) { return s.trim(); }).filter(Boolean);
}

function set(opts) {
  opts = opts || {};
  validateOpts(opts, ["http", "https", "no", "auth"], "proxy.set");
  if (opts.http !== undefined)  STATE.http  = opts.http  ? _parseProxyUrl(opts.http)  : null;
  if (opts.https !== undefined) STATE.https = opts.https ? _parseProxyUrl(opts.https) : null;
  if (opts.no !== undefined)    STATE.noProxy = _parseNoProxy(opts.no);
  if (opts.auth !== undefined)  STATE.auth = opts.auth ? _parseAuth(opts.auth) : null;
  STATE.agentCache.clear();
  _emitObs("network.proxy.set", {
    httpSet:  !!STATE.http,
    httpsSet: !!STATE.https,
    noProxyCount: STATE.noProxy.length,
  });
}

function fromEnv(envObj) {
  var env = envObj || process.env;
  var httpProxy  = env.HTTP_PROXY  || env.http_proxy;
  var httpsProxy = env.HTTPS_PROXY || env.https_proxy;
  var noProxy    = env.NO_PROXY    || env.no_proxy;
  var allProxy   = env.ALL_PROXY   || env.all_proxy;
  var authEnv    = env.BLAMEJS_PROXY_AUTH;
  var changed = false;
  if (httpProxy)  { STATE.http  = _parseProxyUrl(httpProxy);  changed = true; }
  else if (allProxy) { STATE.http = _parseProxyUrl(allProxy); changed = true; }
  if (httpsProxy) { STATE.https = _parseProxyUrl(httpsProxy); changed = true; }
  else if (allProxy) { STATE.https = _parseProxyUrl(allProxy); changed = true; }
  if (noProxy)    { STATE.noProxy = _parseNoProxy(noProxy);   changed = true; }
  if (authEnv)    { STATE.auth = _parseAuth(authEnv);         changed = true; }
  if (changed) {
    STATE.agentCache.clear();
    _emitObs("network.proxy.from_env", {
      httpSet:  !!STATE.http,
      httpsSet: !!STATE.https,
      noProxyCount: STATE.noProxy.length,
    });
  }
  return changed;
}

function _ipv4ToInt(ip) {
  var p = ip.split(".");
  return ((p[0] | 0) << 24 >>> 0) + ((p[1] | 0) << 16) + ((p[2] | 0) << 8) + (p[3] | 0);
}

function _matchCidr(cidr, host) {
  var slash = cidr.indexOf("/");
  if (slash === -1) return false;
  var network = cidr.slice(0, slash);
  var prefix = parseInt(cidr.slice(slash + 1), 10);
  if (net.isIP(host) !== 4 || net.isIP(network) !== 4) return false;
  if (!isFinite(prefix) || prefix < 0 || prefix > IPV4_PREFIX_MAX_BITS) return false;
  if (prefix === 0) return true;
  var mask = (0xffffffff << (IPV4_PREFIX_MAX_BITS - prefix)) >>> 0;
  return (_ipv4ToInt(host) & mask) === (_ipv4ToInt(network) & mask);
}

function _parseTarget(targetUrl) {
  if (targetUrl instanceof URL) return targetUrl;
  return safeUrl.parse(String(targetUrl), {
    allowedProtocols: safeUrl.ALLOW_HTTP_ALL,
    errorClass:       ProxyError,
  });
}

function shouldProxy(targetUrl) {
  var u = _parseTarget(targetUrl);
  var host = u.hostname;
  var rules = STATE.noProxy;
  for (var i = 0; i < rules.length; i++) {
    var r = rules[i];
    if (r === "*") return false;
    if (r.indexOf("/") !== -1 && _matchCidr(r, host)) return false;
    var bare = r.charAt(0) === "." ? r.slice(1) : r;
    if (host === bare) return false;
    if (host.length > bare.length && host.slice(host.length - bare.length - 1) === "." + bare) return false;
  }
  if (u.protocol === "https:") return !!STATE.https;
  if (u.protocol === "http:")  return !!STATE.http;
  return false;
}

function _proxyForUrl(targetUrl) {
  var u = _parseTarget(targetUrl);
  if (!shouldProxy(u)) return null;
  return u.protocol === "https:" ? STATE.https : STATE.http;
}

function _proxyAuthHeader(proxyUrl) {
  var user = proxyUrl.username || (STATE.auth && STATE.auth.user) || "";
  var pass = proxyUrl.password || (STATE.auth && STATE.auth.pass) || "";
  if (!user && !pass) return null;
  return "Basic " + Buffer.from(decodeURIComponent(user) + ":" + decodeURIComponent(pass), "utf8").toString("base64");
}

function _connectThroughTunnel(proxyUrl, targetHost, targetPort, callback) {
  var proxyPort = proxyUrl.port || (proxyUrl.protocol === "https:" ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT);
  var proxySocket = proxyUrl.protocol === "https:"
    ? nodeTls.connect({
        host:       proxyUrl.hostname,
        port:       proxyPort,
        servername: proxyUrl.hostname,
        minVersion: "TLSv1.3",
        ecdhCurve:  C.TLS_GROUP_CURVE_STR,
      })
    : net.connect({ host: proxyUrl.hostname, port: proxyPort });
  var settled = false;
  function done(err, sock) { if (settled) return; settled = true; callback(err, sock); }
  proxySocket.on("error", function (e) { done(e); });
  proxySocket.on(proxyUrl.protocol === "https:" ? "secureConnect" : "connect", function () {
    if (proxyUrl.protocol === "https:") {
      // The CONNECT-tunnel leg to an https proxy is itself a TLS handshake;
      // audit a classical fallback to the proxy too, not only to the upstream.
      pqcAgent()._auditClassicalDowngrade(proxySocket, {
        host: proxyUrl.hostname, port: proxyPort,
      });
    }
    var lines = [
      "CONNECT " + targetHost + ":" + targetPort + " HTTP/1.1",
      "Host: " + targetHost + ":" + targetPort,
    ];
    var auth = _proxyAuthHeader(proxyUrl);
    if (auth) lines.push("Proxy-Authorization: " + auth);
    lines.push("", "");
    proxySocket.write(lines.join("\r\n"));
    var buf = Buffer.alloc(0);
    function onData(chunk) {
      buf = Buffer.concat([buf, chunk]);
      var idx = buf.indexOf("\r\n\r\n");
      if (idx === -1) return;
      proxySocket.removeListener("data", onData);
      var head = buf.slice(0, idx).toString("ascii");
      var status = head.split("\r\n")[0] || "";
      var match = /HTTP\/1\.[01] (\d{3})/.exec(status);
      if (!match || parseInt(match[1], 10) !== 200) {
        done(new ProxyError("proxy/connect-failed", "proxy CONNECT to " + targetHost + ":" + targetPort + " failed: " + status));
        try { proxySocket.destroy(); } catch (_e) { /* best-effort socket teardown */ }
        return;
      }
      done(null, proxySocket);
    }
    proxySocket.on("data", onData);
  });
}

function agentFor(targetUrl) {
  var proxy = _proxyForUrl(targetUrl);
  if (!proxy) return null;
  var u = _parseTarget(targetUrl);
  var key = proxy.toString() + "|" + u.protocol;
  if (STATE.agentCache.has(key)) return STATE.agentCache.get(key);

  var agent;
  if (u.protocol === "https:") {
    agent = new https.Agent({
      keepAlive:  true,
      minVersion: "TLSv1.3",
      ecdhCurve:  C.TLS_GROUP_CURVE_STR,
    });
    agent.createConnection = function (options, cb) {
      _connectThroughTunnel(proxy, options.host, options.port, function (err, tunnel) {
        if (err) return cb(err);
        var secure = nodeTls.connect({
          socket:     tunnel,
          servername: options.servername || options.host,
          minVersion: "TLSv1.3",
          ecdhCurve:  C.TLS_GROUP_CURVE_STR,
          ALPNProtocols: options.ALPNProtocols,
        }, function () {
          // Audit a classical-group fallback on the upstream (target) handshake
          // reached through the proxy tunnel, so the "every outbound TLS path
          // emits tls.classical_downgrade" guarantee holds for proxied requests
          // too (the direct path audits in pqc-agent.create). Drop-silent; the
          // handshake itself is unchanged (still hybrid-preferred TLSv1.3).
          pqcAgent()._auditClassicalDowngrade(secure, {
            host: options.servername || options.host,
            port: options.port,
          });
          cb(null, secure);
        });
        secure.on("error", function (e) { cb(e); });
      });
    };
  } else {
    agent = new http.Agent({ keepAlive: true });
    agent.createConnection = function (options, cb) {
      _connectThroughTunnel(proxy, options.host, options.port, function (err, tunnel) {
        if (err) return cb(err);
        cb(null, tunnel);
      });
    };
  }
  STATE.agentCache.set(key, agent);
  _emitObs("network.proxy.agent.created", { protocol: u.protocol });
  return agent;
}

function snapshot() {
  return {
    http:    STATE.http  ? STATE.http.toString()  : null,
    https:   STATE.https ? STATE.https.toString() : null,
    noProxy: STATE.noProxy.slice(),
    authSet: !!STATE.auth,
  };
}

function _emitObs(name, fields) {
  try { observability().emit(name, fields || {}); } catch (_e) { /* obs best-effort */ }
}

function _resetForTest() {
  STATE.http = null; STATE.https = null; STATE.noProxy = []; STATE.auth = null;
  STATE.agentCache.clear();
}

module.exports = {
  set:           set,
  fromEnv:       fromEnv,
  shouldProxy:   shouldProxy,
  agentFor:      agentFor,
  snapshot:      snapshot,
  ProxyError:    ProxyError,
  _resetForTest: _resetForTest,
};

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var http = require("node:http");
var https = require("node:https");
var net = require("node:net");
var nodeTls = require("node:tls");

var C = require("./constants");
var lazyRequire = require("./lazy-require");
var safeBuffer = require("./safe-buffer");
var ipUtils = require("./ip-utils");
var safeUrl = require("./safe-url");
var ssrfGuard = require("./ssrf-guard");
var validateOpts = require("./validate-opts");
var { defineClass } = require("./framework-error");

var ProxyError = defineClass("ProxyError", { alwaysPermanent: false });

var DEFAULT_HTTPS_PORT   = 443;
var DEFAULT_HTTP_PORT    = C.BYTES.bytes(80);

var TUNNEL_HEADER_MAX_BYTES = C.BYTES.kib(64);
var TUNNEL_CONNECT_TIMEOUT_MS = C.TIME.seconds(30);
var _testConnectTimeoutMs = null;
function _connectTimeoutMs() {
  return typeof _testConnectTimeoutMs === "number" ? _testConnectTimeoutMs : TUNNEL_CONNECT_TIMEOUT_MS;
}

var observability = lazyRequire(function () { return require("./observability"); });
// Lazy so pqc-agent's TLS/audit graph isn't pulled into every process that
// imports network-proxy but never proxies an https upstream. Used only to audit
// a classical-group fallback on a proxy-tunneled TLS handshake (the direct path
// audits in pqc-agent.create()).
var pqcAgent = lazyRequire(function () { return require("./pqc-agent"); });
// networkTls — lazy so the outbound-TLS posture is read from live state at
// dial time (an operator's preferredGroups.set must reach the next
// connection), without pulling the TLS module into this one's boot graph.
var networkTls = lazyRequire(function () { return require("./network-tls"); });

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
      allowUserinfo:    true,
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
  observability().safeEvent("network.proxy.set", 1, {
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
    observability().safeEvent("network.proxy.from_env", 1, {
      httpSet:  !!STATE.http,
      httpsSet: !!STATE.https,
      noProxyCount: STATE.noProxy.length,
    });
  }
  return changed;
}

function _noProxyRuleMatches(rule, host) {
  if (rule === "*") return true;
  var slash = rule.indexOf("/");
  if (slash !== -1) {
    var cidr = ssrfGuard._canonicalListEntry(ipUtils.dialHost(rule.slice(0, slash)) + rule.slice(slash));
    return ssrfGuard._listMatches([cidr], host, false);
  }
  if (ipUtils.canonicalIp(rule) !== null) {
    if (rule.indexOf("%") !== -1 || host.indexOf("%") !== -1) return ipUtils.sameAddress(rule, host);
    return ssrfGuard._sameAddress(rule, host);
  }
  var bare = (rule.charAt(0) === "." ? rule.slice(1) : rule).toLowerCase();
  if (host === bare) return true;
  return host.length > bare.length && host.slice(host.length - bare.length - 1) === "." + bare;
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
  var host = ipUtils.dialHost(u.hostname);
  var rules = STATE.noProxy;
  for (var i = 0; i < rules.length; i++) {
    if (_noProxyRuleMatches(rules[i], host)) return false;
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

var REQUEST_TLS_CREDENTIALS = ["ca", "cert", "key", "pfx", "passphrase"];

function _clientTlsOptions(base) {
  return networkTls().applyToContext({ base: base, role: "client" });
}

function _connectThroughTunnel(proxyUrl, targetHost, targetPort, callback) {
  var proxyPort = proxyUrl.port || (proxyUrl.protocol === "https:" ? DEFAULT_HTTPS_PORT : DEFAULT_HTTP_PORT);
  var proxyPosture = proxyUrl.protocol === "https:" ? _clientTlsOptions(networkTls().outboundPosture()) : null;
  var proxyHost = ipUtils.dialHost(proxyUrl.hostname);
  var targetAuthority = ipUtils.hostPort(targetHost, targetPort);
  var proxySocket = proxyUrl.protocol === "https:"
    ? nodeTls.connect(Object.assign({
      host:       proxyHost,
      port:       proxyPort,
      servername: networkTls().sniFor(proxyHost),
    }, proxyPosture))
    : net.connect({ host: proxyHost, port: proxyPort });
  var settled = false;
  var connectDeadline = null;
  function done(err, sock) {
    if (settled) return;
    settled = true;
    // allow:handrolled-debounce-oneshot-connect-deadline — armed once for the CONNECT and cleared when it settles; nothing re-arms it
    if (connectDeadline) { try { clearTimeout(connectDeadline); } catch (_e) { /* best-effort */ } connectDeadline = null; }
    callback(err, sock);
  }
  var connectTimeoutMs = _connectTimeoutMs();
  connectDeadline = setTimeout(function () {
    done(new ProxyError("proxy/connect-timeout",
      "proxy CONNECT to " + targetAuthority + " timed out after " +
      connectTimeoutMs + "ms"));
    try { proxySocket.destroy(); } catch (_e) { /* best-effort socket teardown */ }
  }, connectTimeoutMs);
  if (connectDeadline && typeof connectDeadline.unref === "function") connectDeadline.unref();
  proxySocket.on("error", function (e) {
    if (proxyPosture) {
      networkTls().annotateOutboundFailure(e, {
        host:    proxyUrl.hostname,   // allow:url-hostname-not-dialed (names the proxy in the error message)
        port:    Number(proxyPort),
        tlsOpts: proxyPosture,
      });
    }
    done(e);
  });
  var proxyConnected = false;
  function onPeerClosed() {
    if (settled) return;
    done(new ProxyError("proxy/connect-closed",
      "proxy closed the connection before completing its CONNECT reply for " +
      targetAuthority));
    try { proxySocket.destroy(); } catch (_e) { /* best-effort socket teardown */ }
  }
  function onPeerEnd() {
    if (proxyConnected) onPeerClosed();
  }
  proxySocket.on("end", onPeerEnd);
  proxySocket.on("close", onPeerClosed);
  proxySocket.on(proxyUrl.protocol === "https:" ? "secureConnect" : "connect", function () {
    proxyConnected = true;
    if (proxyUrl.protocol === "https:") {
      pqcAgent()._auditClassicalDowngrade(proxySocket, {
        host: proxyUrl.hostname, port: proxyPort,   // allow:url-hostname-not-dialed (audit metadata)
      });
    }
    var lines = [
      "CONNECT " + targetAuthority + " HTTP/1.1",
      "Host: " + targetAuthority,
    ];
    var auth = _proxyAuthHeader(proxyUrl);
    if (auth) lines.push("Proxy-Authorization: " + auth);
    lines.push("", "");
    proxySocket.write(lines.join("\r\n"));
    var buf = Buffer.alloc(0);
    function onData(chunk) {
      buf = Buffer.concat([buf, chunk]);
      var idx = buf.indexOf("\r\n\r\n");
      if (idx === -1) {
        if (safeBuffer.byteLengthOf(buf) > TUNNEL_HEADER_MAX_BYTES) {
          proxySocket.removeListener("data", onData);
          done(new ProxyError("proxy/connect-headers-too-large",
            "proxy CONNECT reply exceeded " + TUNNEL_HEADER_MAX_BYTES +
            " bytes before CRLFCRLF"));
          try { proxySocket.destroy(); } catch (_e) { /* best-effort socket teardown */ }
        }
        return;
      }
      proxySocket.removeListener("data", onData);
      var head = buf.slice(0, idx).toString("ascii");
      var status = head.split("\r\n")[0] || "";
      var match = /HTTP\/1\.[01] (\d{3})/.exec(status);
      if (!match || parseInt(match[1], 10) !== 200) {
        done(new ProxyError("proxy/connect-failed", "proxy CONNECT to " + targetAuthority + " failed: " + status));
        try { proxySocket.destroy(); } catch (_e) { /* best-effort socket teardown */ }
        return;
      }
      proxySocket.removeListener("end", onPeerEnd);
      proxySocket.removeListener("close", onPeerClosed);
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
    agent = new https.Agent(Object.assign({
      keepAlive:           true,
      checkServerIdentity: networkTls()._withCompromisedChainCheck(),
    }, networkTls().outboundPosture()));
    agent.createConnection = function (options, cb) {
      var targetHost = ipUtils.dialHost(options.host);
      var identity;
      try {
        identity = networkTls().identityFor(targetHost, options.servername || undefined, {
          label: "proxy agent: servername", errorClass: ProxyError, code: "proxy/bad-servername",
        });
        networkTls()._assertCaNotCompromised(options.ca, {
          errorClass: ProxyError, code: "proxy/compromised-key", label: "proxy agent: ca",
        });
      } catch (e) { return cb(e); }
      var answered = false;
      function answer(err, sock) {
        if (answered) return;
        answered = true;
        cb(err, sock);
      }
      _connectThroughTunnel(proxy, targetHost, options.port, function (err, tunnel) {
        if (err) return answer(err);
        var livePosture;
        var secure;
        try {
          livePosture = networkTls().outboundPosture();
          var tunnelTls = _clientTlsOptions(Object.assign({
            socket:     tunnel,
            host:       targetHost,
            ALPNProtocols: options.ALPNProtocols,
            checkServerIdentity: options.checkServerIdentity,
          }, identity, livePosture));
          REQUEST_TLS_CREDENTIALS.forEach(function (k) {
            if (options[k] !== undefined && options[k] !== null) tunnelTls[k] = options[k];
          });
          if (options.ca !== undefined && options.ca !== null) {
            tunnelTls.checkServerIdentity = networkTls()._withCompromisedChainCheck(tunnelTls.checkServerIdentity,
              options.ca);
          }
          secure = nodeTls.connect(tunnelTls, function () {
            // Audits a classical downgrade on the proxied path. Drop-silent.
            pqcAgent()._auditClassicalDowngrade(secure, {
              host: options.servername || options.host,
              port: options.port,
            });
            answer(null, secure);
          });
        } catch (e) {
          try { tunnel.destroy(); } catch (_e) { /* best-effort socket teardown */ }
          return answer(e);
        }
        secure.on("error", function (e) {
          networkTls().annotateOutboundFailure(e, {
            host:    options.servername || options.host,
            port:    Number(options.port),
            tlsOpts: livePosture,
          });
          answer(e);
        });
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
  pqcAgent()._guardPooledSocketReuse(agent);
  STATE.agentCache.set(key, agent);
  observability().safeEvent("network.proxy.agent.created", 1, { protocol: u.protocol });
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

function _resetForTest() {
  STATE.http = null; STATE.https = null; STATE.noProxy = []; STATE.auth = null;
  STATE.agentCache.clear();
  _testConnectTimeoutMs = null;
}

function _setConnectTimeoutForTest(ms) { _testConnectTimeoutMs = ms; }

module.exports = {
  set:           set,
  fromEnv:       fromEnv,
  shouldProxy:   shouldProxy,
  agentFor:      agentFor,
  snapshot:      snapshot,
  ProxyError:    ProxyError,
  _resetForTest: _resetForTest,
  _setConnectTimeoutForTest: _setConnectTimeoutForTest,
};

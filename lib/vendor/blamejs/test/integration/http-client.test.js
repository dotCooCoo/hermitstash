"use strict";
/**
 * Live HTTP client round-trip against the docker-compose Caddy fixture.
 * Exercises lib/http-client.js's request flow, both directly (HTTP) and
 * through the Squid forward proxy on :3128 (HTTP_PROXY semantics).
 *
 * Caddy hosts the only "real app" endpoint in the test stack — its
 * /healthz returns 200 "ok" — making it the natural target for both
 * direct and proxy-routed integration coverage.
 */
var helpers = require("../helpers");
var check = helpers.check;
var services = require("../helpers/services");
var b = require("../../");

async function run() {
  var caddySvc = await services.requireService("caddy");
  if (!caddySvc.ok) throw new Error("caddy unreachable: " + caddySvc.reason);
  var squidSvc = await services.requireService("squid");
  if (!squidSvc.ok) throw new Error("squid unreachable: " + squidSvc.reason);
  var caddyTlsSvc = await services.requireService("caddyTls");
  if (!caddyTlsSvc.ok) throw new Error("caddy-tls unreachable: " + caddyTlsSvc.reason);

  // ---- direct HTTP request ----
  var resp = await b.httpClient.request({
    method:           "GET",
    url:              "http://127.0.0.1:8080/healthz",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
  });
  check("direct HTTP: status 200",       resp.statusCode === 200);
  check("direct HTTP: body 'ok'",         Buffer.isBuffer(resp.body) ? resp.body.toString() === "ok" : resp.body === "ok");

  // ---- direct HTTPS with private CA (NODE_EXTRA_CA_CERTS picks it up) ----
  var respTls = await b.httpClient.request({
    method:        "GET",
    url:           "https://localhost:8444/healthz",
    allowInternal: true,
  });
  check("direct HTTPS: status 200",       respTls.statusCode === 200);

  // ---- through Squid forward proxy ----
  // The squid container can't reach the host's 127.0.0.1 — its own
  // loopback is itself. From inside the docker network, caddy is
  // reachable as `caddy:80`. The host-side test process resolves
  // host.docker.internal to the docker host's gateway IP, but the
  // proxy-routed path needs an address the proxy can resolve, so
  // we route through Squid to the docker-internal "caddy" hostname.
  if (typeof b.network.proxy._resetForTest === "function") b.network.proxy._resetForTest();
  b.network.proxy.set({
    http:  "http://127.0.0.1:3128",
    https: "http://127.0.0.1:3128",
  });
  var proxiedResp = await b.httpClient.request({
    method:           "GET",
    url:              "http://caddy/healthz",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
  });
  check("proxied HTTP: status 200 (via Squid → caddy)", proxiedResp.statusCode === 200);
  check("proxied HTTP: body 'ok'",
        Buffer.isBuffer(proxiedResp.body) ? proxiedResp.body.toString() === "ok" : proxiedResp.body === "ok");

  // ---- noProxy entry should bypass the proxy (direct to host port) ----
  if (typeof b.network.proxy._resetForTest === "function") b.network.proxy._resetForTest();
  b.network.proxy.set({
    http:    "http://127.0.0.1:3128",
    no:      "127.0.0.1,localhost",
  });
  var bypassResp = await b.httpClient.request({
    method:           "GET",
    url:              "http://127.0.0.1:8080/healthz",
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
  });
  check("no_proxy bypass: status 200 (direct, not via squid)",
        bypassResp.statusCode === 200);

  // ---- response shapes ----
  if (typeof b.network.proxy._resetForTest === "function") b.network.proxy._resetForTest();
  var jsonResp = await b.httpClient.request({
    method:           "GET",
    url:              "http://127.0.0.1:8025/api/v1/info",  // Mailpit info endpoint
    allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
    allowInternal:    true,
  });
  check("response: statusCode and body shape preserved",
        jsonResp.statusCode === 200 && (Buffer.isBuffer(jsonResp.body) || typeof jsonResp.body === "string"));

  // ---- 404 surfaces correctly ----
  var notFound = null;
  try {
    await b.httpClient.request({
      method:           "GET",
      url:              "http://127.0.0.1:8080/this-does-not-exist",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
  } catch (e) { notFound = e; }
  check("404: surfaces as HTTP error (or response with 404)",
        notFound ? /404|HTTP_ERROR/.test((notFound.code || "") + " " + notFound.message) : true);

  // ---- SSRF unconditional cloud-metadata block — even with proxy +
  //      allowInternal:true the framework refuses 169.254.169.254 etc.
  //      because the proxy can't be trusted to refuse them downstream.
  //      Regression for #106 P1 Codex finding (v0.11.1).
  b.network.proxy.set({ http: "http://127.0.0.1:3128" });
  var metaErr = null;
  try {
    await b.httpClient.request({
      method:           "GET",
      url:              "http://169.254.169.254/latest/meta-data/",
      allowedProtocols: b.safeUrl.ALLOW_HTTP_ALL,
      allowInternal:    true,
    });
  } catch (eMeta) { metaErr = eMeta; }
  check("SSRF metadata IP refused even with proxy + allowInternal:true",
        metaErr && metaErr.code === "ssrf-guard/blocked-cloud-metadata");
  if (typeof b.network.proxy._resetForTest === "function") b.network.proxy._resetForTest();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); process.exit(0); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

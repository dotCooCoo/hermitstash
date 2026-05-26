"use strict";
/**
 * Layer 0 — b.middleware.botGuard.
 * Focus: the Sec-Fetch-Mode heuristic must never refuse a real browser.
 * Browsers omit Fetch Metadata (Sec-Fetch-*) on plain-HTTP non-localhost
 * origins (Umbrel, LAN / *.local reverse proxies) AND in Safari < 16.4
 * even over HTTPS — so a missing Sec-Fetch-Mode is advisory-only (tags in
 * mode:"tag", never blocks). Drive-by bots are still blocked by the
 * missing-Accept-Language and User-Agent heuristics.
 */

var b = require("../../index");
var helpers = require("../helpers");
var check = helpers.check;

var BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36";

function _run(opts, reqInit) {
  var mw = b.middleware.botGuard(opts || {});
  var req = b.testing.mockReq(reqInit);
  var res = b.testing.mockRes();
  var nexted = false;
  mw(req, res, function () { nexted = true; });
  var cap = res._captured();
  return { nexted: nexted, blocked: cap.status === 403, status: cap.status, body: cap.body, suspectedBot: req.suspectedBot };
}

function testSurface() {
  check("b.middleware.botGuard is a function", typeof b.middleware.botGuard === "function");
  check("returns a (req,res,next) middleware", b.middleware.botGuard({}).length === 3);
}

function testSecFetchNeverBlocks() {
  // The reported defect: a real browser on a plain-HTTP non-localhost
  // origin (Umbrel app / LAN proxy) sends Accept-Language but no Sec-Fetch-*.
  var umbrel = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en-US", "user-agent": BROWSER_UA, host: "umbrel-dev.local:3080" } });
  check("plain-HTTP browser (Umbrel) is NOT blocked", umbrel.nexted && !umbrel.blocked);

  // Safari < 16.4 omits Sec-Fetch-* even over HTTPS — must not 403 either.
  var safari = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en-US", "user-agent": "Mozilla/5.0 (Macintosh) Version/15.6 Safari/605", host: "app.example.com" }, socket: { encrypted: true } });
  check("Safari-over-HTTPS (no Sec-Fetch) is NOT blocked", safari.nexted && !safari.blocked);

  // localhost over plain HTTP, no Sec-Fetch — also fine.
  var local = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": BROWSER_UA, host: "localhost:3000" } });
  check("localhost browser is NOT blocked", local.nexted && !local.blocked);

  // A secure-context browser that DID send Sec-Fetch-Mode passes (sanity).
  var modern = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": BROWSER_UA, "sec-fetch-mode": "navigate", host: "app.example.com" }, socket: { encrypted: true } });
  check("modern HTTPS browser passes", modern.nexted && !modern.blocked);
}

function testBotsStillBlocked() {
  // Missing Accept-Language remains a hard block.
  var noLang = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "user-agent": BROWSER_UA, host: "app.example.com" }, socket: { encrypted: true } });
  check("missing Accept-Language is blocked", noLang.blocked && noLang.status === 403 && noLang.body === "Forbidden");

  // Known automation UA remains a hard block.
  var curl = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": "curl/8.4.0", host: "app.example.com" } });
  check("curl UA is blocked", curl.blocked && curl.status === 403);

  var py = _run({ mode: "block" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": "python-requests/2.31.0", host: "x" } });
  check("python-requests UA is blocked", py.blocked);
}

function testTagModeAdvisory() {
  // mode:"tag" — secure context, no Sec-Fetch-Mode → advisory tag, never blocks.
  var tagged = _run({ mode: "tag" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": BROWSER_UA, host: "app.example.com" }, socket: { encrypted: true } });
  check("tag mode: secure-context Sec-Fetch miss tags but continues", tagged.nexted && !tagged.blocked && tagged.suspectedBot === "missing-sec-fetch-mode");

  // mode:"tag" — plain-HTTP non-localhost → NOT tagged for Sec-Fetch (insecure context).
  var untagged = _run({ mode: "tag" }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": BROWSER_UA, host: "umbrel.local" } });
  check("tag mode: plain-HTTP origin is NOT tagged for Sec-Fetch", untagged.nexted && !untagged.suspectedBot);
}

function testOverridesAndSkips() {
  // allowedAgents override beats the deny-list.
  var allowed = _run({ mode: "block", allowedAgents: [/^curl\//i] }, { method: "GET", url: "/", headers: { "accept-language": "en", "user-agent": "curl/8.4.0", host: "x" } });
  check("allowedAgents override lets curl through", allowed.nexted && !allowed.blocked);

  // API routes skip the browser-fingerprint checks (onlyForHtml default).
  var api = _run({ mode: "block" }, { method: "GET", url: "/api/data", pathname: "/api/data", headers: { "user-agent": BROWSER_UA, host: "x" } });
  check("API route skips fingerprint checks", api.nexted && !api.blocked);

  // skipPaths bypass.
  var skipped = _run({ mode: "block", skipPaths: ["/healthz"] }, { method: "GET", url: "/healthz", pathname: "/healthz", headers: { "user-agent": "curl/8" } });
  check("skipPaths bypasses bot-guard", skipped.nexted && !skipped.blocked);

  // RegExp patterns are required (string patterns refused at create()).
  var threw = null;
  try { b.middleware.botGuard({ blockedAgents: ["badbot"] }); } catch (e) { threw = e.code; }
  check("string blockedAgents pattern is refused", threw === "bot-guard/bad-pattern");
}

async function run() {
  testSurface();
  testSecFetchNeverBlocks();
  testBotsStillBlocked();
  testTagModeAdvisory();
  testOverridesAndSkips();
}
module.exports = { run: run };
if (require.main === module) { run().then(function () { console.log("[bot-guard] OK — " + helpers.getChecks() + " checks passed"); }, function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }); }

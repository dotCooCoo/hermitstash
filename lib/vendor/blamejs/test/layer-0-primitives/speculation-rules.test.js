"use strict";
/**
 * speculation-rules — W3C Speculation Rules emitter middleware.
 *
 * Run standalone: `node test/layer-0-primitives/speculation-rules.test.js`
 * Or via smoke:   `node test/smoke.js`
 */

var helpers = require("../helpers");
var b        = helpers.b;
var check    = helpers.check;
var _mockReq = helpers._mockReq;
var _mockRes = helpers._mockRes;

function testSurface() {
  check("b.middleware.speculationRules is a function",
        typeof b.middleware.speculationRules === "function");
  var raw = b.middleware._modules.speculationRules;
  check("EAGERNESS_LEVELS exposed",
        Array.isArray(raw.EAGERNESS_LEVELS) &&
        raw.EAGERNESS_LEVELS.indexOf("moderate") !== -1);
  check("ACTION_KEYS exposed",
        Array.isArray(raw.ACTION_KEYS) &&
        raw.ACTION_KEYS.indexOf("prerender") !== -1 &&
        raw.ACTION_KEYS.indexOf("prefetch")  !== -1);
}

function testValidatesRulesShape() {
  var threw;
  threw = null;
  try { b.middleware.speculationRules({}); } catch (e) { threw = e; }
  check("missing rules + rulesUrl throws",
        threw && /opts.rulesUrl|opts.rules/.test(threw.message));

  threw = null;
  try { b.middleware.speculationRules({ rules: { prerender: "not-array" } }); } catch (e) { threw = e; }
  check("non-array prerender throws",
        threw && /must be an array/.test(threw.message));

  threw = null;
  try {
    b.middleware.speculationRules({
      rules: { prerender: [{ where: { href_matches: "/x" } }] },
    });
  } catch (e) { threw = e; }
  check("missing eagerness throws",
        threw && /eagerness/.test(threw.message));

  threw = null;
  try {
    b.middleware.speculationRules({
      rules: { prefetch: [{ where: { href_matches: "/x" }, eagerness: "ludicrous" }] },
    });
  } catch (e) { threw = e; }
  check("unknown eagerness rejected",
        threw && /eagerness/.test(threw.message));

  threw = null;
  try {
    b.middleware.speculationRules({
      rules: { prefetch: [{ where: "string", eagerness: "moderate" }] },
    });
  } catch (e) { threw = e; }
  check("non-object where rejected",
        threw && /\.where/.test(threw.message));

  threw = null;
  try { b.middleware.speculationRules({ rules: {} }); } catch (e) { threw = e; }
  check("empty rules object rejected",
        threw && /at least one of/.test(threw.message));
}

function testRejectsBothRulesAndUrlInHeaderMode() {
  var threw = null;
  try {
    b.middleware.speculationRules({
      rules:    { prerender: [{ where: { href_matches: "/x" }, eagerness: "moderate" }] },
      rulesUrl: "/rules.json",
    });
  } catch (e) { threw = e; }
  check("rules + rulesUrl both set rejected",
        threw && /not both/.test(threw.message));
}

function testRulesUrlInjection() {
  var threw = null;
  try { b.middleware.speculationRules({ rulesUrl: "/rules\r\nX-Inject: 1" }); }
  catch (e) { threw = e; }
  check("CR/LF in rulesUrl refused",
        threw && /header-injection/.test(threw.message));
}

function testInlineRequiresRules() {
  var threw = null;
  try { b.middleware.speculationRules({ inline: true, rulesUrl: "/rules.json" }); }
  catch (e) { threw = e; }
  check("inline:true without rules throws",
        threw && /opts\.rules is required/.test(threw.message));
}

function _drive(mw, req, res) {
  return new Promise(function (resolve) {
    mw(req, res, function () { resolve(); });
  });
}

async function testHeaderModeWithRulesUrl() {
  var mw = b.middleware.speculationRules({ rulesUrl: "/rules/speculation.json" });
  var req = _mockReq();
  var res = _mockRes();
  await _drive(mw, req, res);
  var captured = res._captured();
  var hdr = captured.headers["speculation-rules"];
  check("Speculation-Rules header set",       typeof hdr === "string" && hdr.length > 0);
  check("header value is quoted URL string",   hdr === '"/rules/speculation.json"');
}

async function testHeaderModeWithRulesObjectEmitsDataUrl() {
  var mw = b.middleware.speculationRules({
    rules: {
      prerender: [{ where: { href_matches: "/articles/*" }, eagerness: "moderate" }],
    },
  });
  var req = _mockReq();
  var res = _mockRes();
  await _drive(mw, req, res);
  var captured = res._captured();
  var hdr = captured.headers["speculation-rules"];
  check("header is a quoted data: URL",
        hdr.indexOf('"data:application/speculationrules+json;base64,') === 0 &&
        hdr.charAt(hdr.length - 1) === '"');
  // Round-trip the base64 to confirm the rules survived.
  var b64 = hdr.slice('"data:application/speculationrules+json;base64,'.length, hdr.length - 1);
  var parsed = JSON.parse(Buffer.from(b64, "base64").toString("utf8"));
  check("data: URL round-trips back to the rules JSON",
        Array.isArray(parsed.prerender) &&
        parsed.prerender[0].eagerness === "moderate");
}

async function testInlineModeInjectsScriptIntoHtml() {
  var mw = b.middleware.speculationRules({
    inline: true,
    rules: {
      prefetch: [{ where: { href_matches: "/api/*" }, eagerness: "conservative" }],
    },
  });
  var req = _mockReq();
  // Manually construct a res that lets us drive write/end and inspect
  // the buffered body — _mockRes() doesn't have res.write, which the
  // inline-injection path relies on.
  var headers = { "content-type": "text/html; charset=utf-8" };
  var bodyChunks = [];
  var res = {
    setHeader:  function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader:  function (k) { return headers[k.toLowerCase()]; },
    writeHead:  function () {},
    write:      function (chunk) { bodyChunks.push(chunk); return true; },
    end:        function (chunk) { if (chunk !== undefined) bodyChunks.push(chunk); },
  };
  await _drive(mw, req, res);
  var html = "<!doctype html><html><head><title>x</title></head><body><p>hi</p></body></html>";
  res.end(html);
  var body = Buffer.concat(bodyChunks.map(function (c) {
    return Buffer.isBuffer(c) ? c : Buffer.from(String(c), "utf8");
  })).toString("utf8");
  check("script tag injected before </head>",
        body.indexOf('<script type="speculationrules">') !== -1 &&
        body.indexOf("</script></head>") !== -1);
  check("inline rules body contains the prefetch entry",
        body.indexOf('"href_matches":"/api/*"') !== -1);
  check("no Speculation-Rules header set in inline mode",
        headers["speculation-rules"] === undefined);
}

async function testInlineModeSkipsNonHtmlResponses() {
  var mw = b.middleware.speculationRules({
    inline: true,
    rules: {
      prerender: [{ where: { href_matches: "/x" }, eagerness: "moderate" }],
    },
  });
  var req = _mockReq();
  var headers = { "content-type": "application/json" };
  var bodyChunks = [];
  var res = {
    setHeader:  function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader:  function (k) { return headers[k.toLowerCase()]; },
    writeHead:  function () {},
    write:      function (chunk) { bodyChunks.push(chunk); return true; },
    end:        function (chunk) { if (chunk !== undefined) bodyChunks.push(chunk); },
  };
  await _drive(mw, req, res);
  res.end('{"ok":true}');
  var body = Buffer.concat(bodyChunks.map(function (c) {
    return Buffer.isBuffer(c) ? c : Buffer.from(String(c), "utf8");
  })).toString("utf8");
  check("non-HTML response untouched",
        body === '{"ok":true}' &&
        body.indexOf("speculationrules") === -1);
}

async function testInlineModeAddsCspNonceWhenPresent() {
  var mw = b.middleware.speculationRules({
    inline: true,
    rules: {
      prefetch: [{ where: { href_matches: "/x" }, eagerness: "eager" }],
    },
  });
  var req = _mockReq();
  req.cspNonce = "ABC123==";
  var headers = { "content-type": "text/html" };
  var bodyChunks = [];
  var res = {
    setHeader:  function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader:  function (k) { return headers[k.toLowerCase()]; },
    writeHead:  function () {},
    write:      function (chunk) { bodyChunks.push(chunk); return true; },
    end:        function (chunk) { if (chunk !== undefined) bodyChunks.push(chunk); },
  };
  await _drive(mw, req, res);
  res.end("<head></head><body></body>");
  var body = Buffer.concat(bodyChunks.map(function (c) {
    return Buffer.isBuffer(c) ? c : Buffer.from(String(c), "utf8");
  })).toString("utf8");
  check("injected script tag carries req.cspNonce",
        body.indexOf('<script type="speculationrules" nonce="ABC123==">') !== -1);
}

async function testInlineModeFallbackInjectsBeforeBody() {
  var mw = b.middleware.speculationRules({
    inline: true,
    rules: {
      prefetch: [{ where: { href_matches: "/x" }, eagerness: "eager" }],
    },
  });
  var req = _mockReq();
  var headers = { "content-type": "text/html" };
  var bodyChunks = [];
  var res = {
    setHeader:  function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader:  function (k) { return headers[k.toLowerCase()]; },
    writeHead:  function () {},
    write:      function (chunk) { bodyChunks.push(chunk); return true; },
    end:        function (chunk) { if (chunk !== undefined) bodyChunks.push(chunk); },
  };
  await _drive(mw, req, res);
  // No <head>, just a body — fall through to inject after <body>
  res.end("<body><p>x</p></body>");
  var body = Buffer.concat(bodyChunks.map(function (c) {
    return Buffer.isBuffer(c) ? c : Buffer.from(String(c), "utf8");
  })).toString("utf8");
  check("script injected after <body> when no </head> present",
        body.indexOf("<body><script") !== -1);
}

async function testInjectsOnlyOnce() {
  var mw = b.middleware.speculationRules({
    inline: true,
    rules: {
      prerender: [{ where: { href_matches: "/x" }, eagerness: "moderate" }],
    },
  });
  var req = _mockReq();
  var headers = { "content-type": "text/html" };
  var bodyChunks = [];
  var res = {
    setHeader:  function (k, v) { headers[k.toLowerCase()] = v; },
    getHeader:  function (k) { return headers[k.toLowerCase()]; },
    writeHead:  function () {},
    write:      function (chunk) { bodyChunks.push(chunk); return true; },
    end:        function (chunk) { if (chunk !== undefined) bodyChunks.push(chunk); },
  };
  await _drive(mw, req, res);
  res.write("<head></head><body>");
  res.write("<p>more</p>");
  res.end("</body>");
  var body = Buffer.concat(bodyChunks.map(function (c) {
    return Buffer.isBuffer(c) ? c : Buffer.from(String(c), "utf8");
  })).toString("utf8");
  var matches = body.match(/speculationrules/g) || [];
  check("script tag injected exactly once across multiple chunks",
        matches.length === 1);
}

function testRejectsUnknownOpts() {
  var threw = null;
  try {
    b.middleware.speculationRules({
      rulesUrl:   "/rules.json",
      unknownKey: "smell",
    });
  } catch (e) { threw = e; }
  check("unknown opt key rejected", threw !== null);
}

async function run() {
  testSurface();
  testValidatesRulesShape();
  testRejectsBothRulesAndUrlInHeaderMode();
  testRulesUrlInjection();
  testInlineRequiresRules();
  testRejectsUnknownOpts();
  await testHeaderModeWithRulesUrl();
  await testHeaderModeWithRulesObjectEmitsDataUrl();
  await testInlineModeInjectsScriptIntoHtml();
  await testInlineModeSkipsNonHtmlResponses();
  await testInlineModeAddsCspNonceWhenPresent();
  await testInlineModeFallbackInjectsBeforeBody();
  await testInjectsOnlyOnce();
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.message); process.exit(1); }
  );
}

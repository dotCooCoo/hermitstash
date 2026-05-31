"use strict";
/**
 * b.middleware.sse — Server-Sent Events.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

var sseModule = require("../../lib/middleware/sse");

// Mock ServerResponse — captures writeHead + write + end.
function _mockRes() {
  var headers = {};
  var status = null;
  var chunks = [];
  var ended = false;
  var listeners = {};
  return {
    writeHead: function (s, h) { status = s; if (h) Object.assign(headers, h); },
    setHeader: function (k, v) { headers[k] = v; },
    getHeader: function (k) { return headers[k]; },
    write:     function (c)   { chunks.push(c); return true; },
    end:       function ()    { ended = true; },
    once:      function (e, fn) { listeners[e] = fn; },
    emit:      function (e)   { var f = listeners[e]; if (f) f(); },
    _captured: function () {
      return {
        status:   status,
        headers:  headers,
        body:     chunks.join(""),
        ended:    ended,
        listeners: listeners,
      };
    },
  };
}

function _mockReq() {
  return { method: "GET", url: "/events", headers: {}, once: function () {} };
}

async function run() {
  // ---- Surface ----
  check("b.middleware.sse is fn",          typeof b.middleware.sse === "function");
  check("b.sse is object",                 typeof b.sse === "object");
  check("b.sse.create is fn",              typeof b.sse.create === "function");
  check("b.sse.serializeEvent is fn",      typeof b.sse.serializeEvent === "function");

  // ---- Top-level b.sse smoke (low-level surface) ----
  var lowEv = b.sse.serializeEvent({ event: "msg", id: "1", data: "hi" });
  check("b.sse.serializeEvent shape", lowEv === "id: 1\nevent: msg\ndata: hi\n\n");
  var lowMulti = b.sse.serializeEvent({ data: "a\nb" });
  check("b.sse.serializeEvent multi-line data splits",
        lowMulti === "data: a\ndata: b\n\n");
  var lowThrew = null;
  try { b.sse.serializeEvent({ event: "fake\nevent: hijack", data: "x" }); }
  catch (e) { lowThrew = e; }
  check("b.sse.serializeEvent refuses LF in event",
        lowThrew && lowThrew.code === "sse/injection");

  // ---- _formatEvent ----
  var fe = sseModule._formatEvent;
  check("formatEvent: data only",
        fe({ data: "hello" }) === "data: hello\n\n");
  check("formatEvent: id + event + data",
        fe({ id: 5, event: "tick", data: "x" }) === "id: 5\nevent: tick\ndata: x\n\n");
  check("formatEvent: object data → JSON",
        fe({ data: { count: 1 } }) === "data: {\"count\":1}\n\n");
  check("formatEvent: multi-line data → multiple data: lines",
        fe({ data: "line1\nline2" }) === "data: line1\ndata: line2\n\n");
  check("formatEvent: retry as ms",
        fe({ retry: 2000, data: "" }) === "retry: 2000\ndata: \n\n");
  function rejects(label, fn, re) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("formatEvent: " + label, threw && re.test(threw.message || ""));
  }
  // CVE-2026-33128 / 29085 / 44217 — newline-injection refused, not
  // silently stripped (silent strip was the original vulnerability).
  rejects("refuses CRLF in id",     function () { fe({ id: "a\nb", data: "x" }); }, /LF\/CR\/NUL/);
  rejects("refuses CRLF in event",  function () { fe({ event: "a\nb", data: "x" }); }, /LF\/CR\/NUL/);
  rejects("rejects negative retry", function () { fe({ retry: -1 }); }, /non-negative/);
  rejects("rejects NaN retry",      function () { fe({ retry: NaN }); }, /non-negative/);

  // ---- create() validation ----
  var threw = null;
  try { b.middleware.sse(); } catch (e) { threw = e; }
  check("create: rejects missing handler", threw && /handler must be/.test(threw.message));
  threw = null;
  try { b.middleware.sse(function () {}, { heartbeatMs: -1 }); } catch (e) { threw = e; }
  check("create: rejects negative heartbeatMs", threw && /heartbeatMs/.test(threw.message));

  // ---- end-to-end: handler emits, channel.send writes, close ends stream ----
  var sent = [];
  var mw = b.middleware.sse(async function (channel) {
    channel.send({ id: 1, event: "tick", data: { n: 1 } });
    sent.push("a");
    channel.send({ data: "plain" });
    sent.push("b");
    channel.close();
  }, { heartbeatMs: false });

  var req = _mockReq();
  var res = _mockRes();
  await mw(req, res);
  var captured = res._captured();
  check("sse: status 200",                captured.status === 200);
  check("sse: Content-Type text/event-stream",
        /text\/event-stream/.test(captured.headers["Content-Type"]));
  check("sse: Cache-Control no-cache",
        /no-cache/.test(captured.headers["Cache-Control"]));
  check("sse: initial colon-newline flush",
        captured.body.indexOf(":\n\n") === 0);
  check("sse: first event present",
        /id: 1\nevent: tick\ndata: {"n":1}\n\n/.test(captured.body));
  check("sse: second event present",
        /data: plain\n\n/.test(captured.body));
  check("sse: handler ran fully",         sent.length === 2);
  check("sse: stream closed",             captured.ended === true);
  check("sse: default sets X-Accel-Buffering: no",
        captured.headers["X-Accel-Buffering"] === "no");

  // ---- proxyBuffer: false suppresses the nginx hint ----
  var mwNB = b.middleware.sse(async function (channel) {
    channel.send({ data: "x" });
    channel.close();
  }, { heartbeatMs: false, proxyBuffer: false });
  var resNB = _mockRes();
  await mwNB(_mockReq(), resNB);
  check("sse: proxyBuffer:false suppresses X-Accel-Buffering",
        resNB._captured().headers["X-Accel-Buffering"] === undefined);

  // ---- onAbort runs on res close ----
  var aborted = false;
  var mw2 = b.middleware.sse(function (channel) {
    channel.onAbort(function () { aborted = true; });
    // Don't close — simulate handler-stays-open
    return new Promise(function () {});
  }, { heartbeatMs: false });
  var req2 = _mockReq();
  var res2 = _mockRes();
  // Fire and forget; we don't await because handler never returns.
  mw2(req2, res2);
  // Trigger res 'close' to simulate client disconnect.
  res2.emit("close");
  await helpers.waitUntil(function () { return aborted === true; }, {
    label: "sse: onAbort fires on res 'close'",
  });
  check("sse: onAbort fires on res close", aborted === true);
}

module.exports = { run: run };

if (require.main === module) {
  run().then(
    function () { console.log("OK — " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e && e.stack || e); process.exit(1); }
  );
}

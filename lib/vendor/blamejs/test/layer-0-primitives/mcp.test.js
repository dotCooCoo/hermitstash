"use strict";
/**
 * b.mcp — Model Context Protocol server-guard primitive.
 */

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

async function run() {
  check("mcp.serverGuard is fn",   typeof b.mcp.serverGuard === "function");
  check("mcp.parseRequest is fn",  typeof b.mcp.parseRequest === "function");
  check("mcp.refuse is fn",        typeof b.mcp.refuse === "function");

  // refuse() round-trip
  var fakeRes = (function () {
    var headers = {}, status = 0, body = "";
    return {
      setHeader: function (k, v) { headers[k] = v; },
      get statusCode() { return status; },
      set statusCode(v) { status = v; },
      end: function (s) { body = s; },
      _captured: function () { return { status: status, body: body, headers: headers }; },
    };
  })();
  b.mcp.refuse(fakeRes, -32700, "parse error", null);
  var cap = fakeRes._captured();
  check("mcp.refuse: status 400", cap.status === 400);
  check("mcp.refuse: JSON-RPC error envelope", cap.body.indexOf("\"error\"") !== -1);

  // ---- parseRequest ----
  var p = b.mcp.parseRequest('{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"echo"}}');
  check("parseRequest: shape",          p.method === "tools/call" && p.id === 1);

  function rejects(label, fn, reCode) {
    var threw = null;
    try { fn(); } catch (e) { threw = e; }
    check("parseRequest: " + label, threw && threw.code === reCode);
  }
  rejects("bad json",        function () { b.mcp.parseRequest("{"); }, "BAD_JSON");
  rejects("bad version",     function () { b.mcp.parseRequest('{"jsonrpc":"1.0","method":"x","id":1}'); }, "BAD_VERSION");
  rejects("missing method",  function () { b.mcp.parseRequest('{"jsonrpc":"2.0","id":1}'); }, "BAD_METHOD");
  rejects("bad id type",     function () { b.mcp.parseRequest('{"jsonrpc":"2.0","method":"x","id":{}}'); }, "BAD_ID");

  // ---- serverGuard surface ----
  var threwBadOpts = null;
  try { b.mcp.serverGuard({ requireBearer: true }); }
  catch (e) { threwBadOpts = e; }
  check("serverGuard: requires verifyBearer when bearer required",
        threwBadOpts && threwBadOpts.code === "BAD_OPTS");

  var guard = b.mcp.serverGuard({
    requireBearer: false,
    redirectUriAllowlist: ["https://op.example/cb"],
    toolAllowlist: ["echo", "search"],
  });
  check("serverGuard: returns middleware fn", typeof guard === "function");
}

module.exports = { run: run };

"use strict";
/**
 * server-liveness.js — protocol-agnostic "is a HermitStash server running?"
 * probe shared by the offline vault tools (vault-key-rotate,
 * vault-passphrase-{setup,rotate,remove}).
 *
 * The old per-tool probe was a plain http.get to /health on the gate port.
 * On a TLS/PQC deployment that never returns an HTTP response — the raw TCP
 * PQC gate pipes the bytes to an internal HTTPS server that rejects the
 * non-handshake first byte and resets the socket — so the http probe always
 * errored out and the guard concluded "no server", letting destructive
 * rotation/seal run against a live server and corrupt the data directory.
 *
 * This replacement is protocol-agnostic: it opens a bare TCP connection to
 * BOTH the public gate port (PORT, default 3000) AND the internal TLS port
 * (INTERNAL_TLS_PORT, default 3001). If EITHER accepts a TCP connection a
 * server is running. Only a clean ECONNREFUSED on BOTH ports is treated as
 * "not running"; any other outcome (connection established, reset after
 * connect, timeout, or any non-ECONNREFUSED error) is treated as "a listener
 * may exist" so the guard fails safe.
 *
 * The port probe only reaches a server in the caller's own network namespace,
 * listening on the ports named in the caller's environment. The guard first
 * reads the data-directory lease (lib/server-lease.js), which a tool sees from
 * any container or host that mounts the same directory, and refuses while any
 * server or other tool holds it fresh. claimDataDir then takes the lease for
 * the calling tool.
 */

var net = require("net");
var C = require("../../lib/constants");
var serverLease = require("../../lib/server-lease");

// Mirror server-main.js's port resolution exactly:
//   gate port  = config.port = n("PORT", 3000)
//   internal   = INTERNAL_TLS_PORT env, default 3001
function gatePort() {
  return Number(process.env.PORT || 3000);
}

function internalTlsPort() {
  return Number(process.env.INTERNAL_TLS_PORT || 3001);
}

var CONNECT_TIMEOUT_MS = 1500;

/**
 * Bare TCP connect to one port on loopback. Resolves to one of:
 *   "listening" — TCP connection established (server is up)
 *   "refused"   — ECONNREFUSED (nothing listening on this port)
 *   "inconclusive" — any other outcome (reset, timeout, other error); a
 *                    listener may exist but isn't completing a clean connect
 */
function probePort(port) {
  return new Promise(function (resolve) {
    var settled = false;
    function done(result) {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch (_e) { /* best-effort */ }
      resolve(result);
    }
    var socket = net.connect({ host: "127.0.0.1", port: port });
    socket.setTimeout(CONNECT_TIMEOUT_MS);
    socket.once("connect", function () { done("listening"); });
    socket.once("timeout", function () { done("inconclusive"); });
    socket.once("error", function (err) {
      done(err && err.code === "ECONNREFUSED" ? "refused" : "inconclusive");
    });
  });
}

/**
 * Resolve to true if a HermitStash server appears to be running on either the
 * gate port or the internal TLS port. Only a clean ECONNREFUSED on BOTH ports
 * yields false ("not running").
 */
async function isServerRunning() {
  var ports = [gatePort(), internalTlsPort()];
  var results = await Promise.all(ports.map(probePort));
  // Running unless EVERY probed port cleanly refused the connection.
  return !results.every(function (r) { return r === "refused"; });
}

/**
 * Drop-in pre-flight guard for the offline vault tools. When the
 * --force-with-server-running override is set, resolves immediately. Otherwise
 * probes both ports; if a server is detected it prints the banner and exits 1.
 *
 * @param {object} opts                  parsed CLI opts
 * @param {string[]} [extraLines]        extra banner lines after the standard
 *                                       "Stop it first…" line (e.g. the rotate
 *                                       tool's data-corruption caution)
 */
async function assertServerNotRunning(opts, extraLines) {
  if (opts && opts.forceWithServerRunning) return;
  var lease = serverLease.read();
  if (lease && lease.fresh) {
    if (lease.unreadable) {
      console.error("ERROR: " + C.PATHS.SERVER_LEASE + " exists and cannot be read, so a HermitStash server");
      console.error("  or another vault tool may be using the data directory.");
      console.error("  Stop it. If nothing is using the data directory, delete that file and re-run.");
    } else {
      console.error("ERROR: " + serverLease.describe(lease) + " holds " + C.PATHS.SERVER_LEASE + ".");
      console.error("  Stop " + (lease.kind === "server" ? "the server" : "that tool") + " first. A process that " +
        "stopped without removing the lease leaves one that expires in " + serverLease.secondsUntilStale(lease) + "s.");
    }
    _printExtra(extraLines);
    process.exit(1);
  }
  var running = await isServerRunning();
  if (!running) return;
  var ports = [gatePort(), internalTlsPort()];
  console.error("ERROR: a HermitStash server appears to be running (port " +
    ports[0] + " or " + ports[1] + ").");
  console.error("  Stop it first, or pass --force-with-server-running.");
  _printExtra(extraLines);
  process.exit(1);
}

/**
 * assertServerNotRunning, then take the data-directory lease as a tool so a
 * server that starts, or another tool, waits until this one exits. With
 * --force-with-server-running neither the check nor the lease is taken.
 *
 * @param {object} opts         parsed CLI opts
 * @param {string} toolName     the script name, shown to other processes
 * @param {string[]} [extraLines]
 */
async function claimDataDir(opts, toolName, extraLines) {
  await assertServerNotRunning(opts, extraLines);
  if (opts && opts.forceWithServerRunning) return;
  // acquire() checks the lease again under its lock, so a server or tool that
  // took it during the port probe is refused here.
  try { serverLease.acquire({ kind: "tool", name: toolName }); }
  catch (e) {
    if (!e || e.code !== "server-lease/held") throw e;
    console.error("ERROR: " + serverLease.describe(e.lease) + " took " + C.PATHS.SERVER_LEASE + " while this tool was starting.");
    console.error("  Stop it first, then re-run.");
    _printExtra(extraLines);
    process.exit(1);
  }
}

function _printExtra(extraLines) {
  if (Array.isArray(extraLines)) {
    for (var i = 0; i < extraLines.length; i++) console.error(extraLines[i]);
  }
}

module.exports = {
  isServerRunning: isServerRunning,
  assertServerNotRunning: assertServerNotRunning,
  claimDataDir: claimDataDir,
  probePort: probePort,
  gatePort: gatePort,
  internalTlsPort: internalTlsPort,
};

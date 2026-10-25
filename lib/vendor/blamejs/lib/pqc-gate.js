// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module b.pqcGate
 * @nav    Crypto
 * @title  PQC Gate
 * @slug   pqc-gate
 *
 * @intro
 *   A TCP front door that reads the TLS ClientHello and lets a connection
 *   through only when the client offered TLS 1.3 and a post-quantum
 *   key-exchange group that the listener behind the gate ranks ahead of
 *   every classical group. A client that offered neither is answered with a
 *   TLS handshake-failure alert and disconnected.
 *
 *   The post-quantum groups exist only in TLS 1.3, so the gate refuses a
 *   ClientHello whose supported_versions extension does not list TLS 1.3,
 *   or that has no such extension, whatever its supported_groups extension
 *   names. The listener must also be able to negotiate TLS 1.3. The gate
 *   cannot see the listener's version settings, and a listener whose
 *   `maxVersion` is below "TLSv1.3", or whose `secureProtocol` pins an
 *   older version, negotiates TLS 1.2 with classical ECDHE with a client
 *   the gate passed. Such a listener cannot be gated.
 *
 *   The listener picks its group from the first of its OpenSSL group
 *   tuples ("/" between tuples, ":" within one) that shares a group with
 *   the client, and within that tuple it takes the client's key share. The
 *   gate therefore counts only the post-quantum groups in tuples ahead of
 *   every classical group. `b.network.tls.serverKeyAgreementGroups()`
 *   writes each post-quantum group in a tuple of its own ahead of the
 *   classical ones. A listener that reaches TLS 1.3 with that string as its
 *   `ecdhCurve` negotiates a post-quantum group with every client the gate
 *   passes. `b.network.tls.applyToContext` and `b.mail.server.tls.context`
 *   write that string. A listener on a flat colon-separated list, or on
 *   OpenSSL's default list (no `ecdhCurve`), can negotiate X25519 with a
 *   client that lists X25519 first and also offers a hybrid, and the gate
 *   passes that client.
 *
 *   The point is harvest-now-decrypt-later. A session whose key exchange
 *   is classical can be recorded today and opened once a quantum computer
 *   can solve the discrete log behind it, whatever the cipher protecting
 *   the bytes. Refusing at the front means a deployment can state that no
 *   session it served is in that recording.
 *
 *   It reads the ClientHello and nothing else: it does not terminate TLS,
 *   so it holds no key and sees no plaintext, and hands the bytes it read
 *   on to the real listener unchanged. The read is bounded in time and in
 *   size, so a client that opens a connection and says nothing, or says
 *   too much, is dropped rather than held.
 *
 *   Loopback bypasses by default, because a health check and a local
 *   probe should not have to speak post-quantum to reach the service.
 *
 * @card
 *   Refuse a TLS connection whose ClientHello offers no TLS 1.3 post-quantum
 *   key exchange, before it reaches the listener. Reads the ClientHello only,
 *   terminates nothing, and bypasses loopback.
 */

var net = require("node:net");
var C = require("./constants");
var { PQC_GROUPS } = require("./constants");
var ipUtils = require("./ip-utils");
var networkTls = require("./network-tls");
var numericBounds = require("./numeric-bounds");
var ssrfGuard = require("./ssrf-guard");
var validateOpts = require("./validate-opts");
var { boot } = require("./log");

var DEFAULT_LOG = boot("pqc-gate");
var DEFAULT_BYPASS = Object.freeze(["127.0.0.1", "::1", "::ffff:127.0.0.1"]);
var DEFAULT_CLIENTHELLO_TIMEOUT_MS = C.TIME.seconds(5);
var DEFAULT_MAX_CLIENTHELLO_BYTES = C.BYTES.kib(16);

// registry: https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6
var TLS_ALERT_HANDSHAKE_FAILURE = Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
var EXT_SUPPORTED_GROUPS = 0x000A;
var EXT_SUPPORTED_VERSIONS = 0x002B;
var TLS13_VERSION = 0x0304;

var PQC_GROUP_ID_BY_NAME = {};
Object.keys(PQC_GROUPS).forEach(function (name) {
  PQC_GROUP_ID_BY_NAME[name.toLowerCase()] = PQC_GROUPS[name];
});

var CLASSICAL_GROUP_NAMES = Object.freeze([
  "x25519", "x448",
  "secp256r1", "prime256v1", "p-256",
  "secp384r1", "p-384",
  "secp521r1", "p-521",
  "brainpoolp256r1", "brainpoolp384r1", "brainpoolp512r1",
  "brainpoolp256r1tls13", "brainpoolp384r1tls13", "brainpoolp512r1tls13",
  "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192",
]);

var GROUPS_SHAPE = "an OpenSSL group string (\"X25519MLKEM768/X25519\") or an array of names";

function _bareGroupName(name) {
  var i = 0;
  while (i < name.length && (name.charAt(i) === "?" || name.charAt(i) === "*")) i += 1;
  return name.slice(i);
}

function _groupTuples(groups, where, strict) {
  var tuples;
  if (typeof groups === "string" && groups.length > 0) {
    tuples = groups.split("/").map(function (t) { return t.split(":"); });
  } else if (Array.isArray(groups) && groups.length > 0) {
    tuples = [groups.slice()];
  } else {
    throw new TypeError(where + ": groups must be " + GROUPS_SHAPE);
  }
  return tuples.map(function (names, ti) {
    return names.map(function (name) {
      if (typeof name !== "string" || _bareGroupName(name).length === 0) {
        throw new TypeError(where + ": groups tuple " + ti + " holds an empty group name");
      }
      var bare = _bareGroupName(name);
      var key = bare.toLowerCase();
      if (Object.prototype.hasOwnProperty.call(PQC_GROUP_ID_BY_NAME, key)) {
        return { name: bare, id: PQC_GROUP_ID_BY_NAME[key] };
      }
      if (strict && CLASSICAL_GROUP_NAMES.indexOf(key) === -1) {
        throw new TypeError(where + ": groups names '" + name + "', which is not a TLS group name");
      }
      return { name: bare, id: null };
    });
  });
}

function _guaranteedPqcIds(tuples, where) {
  var ids = new Set();
  var ti = 0;
  for (; ti < tuples.length; ti += 1) {
    var classical = tuples[ti].some(function (g) { return g.id === null; });
    if (classical) break;
    tuples[ti].forEach(function (g) { ids.add(g.id); });
  }
  if (!where) return ids;
  for (var rest = ti; rest < tuples.length; rest += 1) {
    for (var gi = 0; gi < tuples[rest].length; gi += 1) {
      if (tuples[rest][gi].id !== null) {
        throw new TypeError(where + ": groups places post-quantum group '" + tuples[rest][gi].name +
          "' in or after a tuple holding a classical group; list post-quantum groups in " +
          "\"/\"-separated tuples ahead of every classical group, as in \"X25519MLKEM768/X25519\"");
      }
    }
  }
  if (ids.size === 0) {
    throw new TypeError(where + ": groups names no post-quantum group, so the gate would refuse every client");
  }
  return ids;
}

function _explicitGroupIds(groups, where) {
  return _guaranteedPqcIds(_groupTuples(groups, where, true), where);
}

function _postureGroupIds() {
  var serverGroups = networkTls.serverKeyAgreementGroups();
  if (typeof serverGroups !== "string" || serverGroups.length === 0) return new Set();
  return _guaranteedPqcIds(_groupTuples(serverGroups, "b.pqcGate", false), null);
}

/**
 * @primitive b.pqcGate.acceptedGroupIds
 * @signature b.pqcGate.acceptedGroupIds(groups?)
 * @since     0.21.3
 * @status    stable
 * @compliance soc2
 * @related   b.pqcGate.clientHelloHasPQC, b.pqcGate.create
 *
 * The set of TLS Supported Group codepoints the gate counts as post-quantum,
 * as a `Set` of numbers. These are the members of `b.constants.PQC_GROUPS`
 * that the listener behind the gate lists in its OpenSSL group tuples ahead
 * of the first tuple holding a classical group. A client offering one of
 * them over TLS 1.3 negotiates a post-quantum group with that listener. A
 * post-quantum group the listener does not list, or lists in or after a
 * tuple with a classical group, is not counted: a client offering it and
 * that classical group can negotiate the classical one.
 *
 * With no argument the listener's groups are read from
 * `b.network.tls.serverKeyAgreementGroups()` at the time of the call, so a
 * later `b.network.tls.preferredGroups.set(...)` changes the answer, and a
 * posture that puts a classical group first answers an empty set.
 *
 * `groups` names the listener's groups instead, for a listener whose
 * `ecdhCurve` is not that string. Pass the same OpenSSL group string the
 * listener uses ("/" between tuples, ":" within one; the "?" and "*" name
 * prefixes are read), or an array of names, which is one tuple. Group
 * names match case-insensitively. Each of these throws `TypeError`: a value
 * that is neither a non-empty string nor a non-empty array, an empty name,
 * a name that is not a TLS group (including "DEFAULT", a "-" removal entry
 * and a comma-separated list), a post-quantum group in or after a tuple
 * holding a classical group, and a list with no post-quantum group.
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.pqcGate.acceptedGroupIds("MLKEM1024/X25519MLKEM768/X25519");
 *   // → Set { 514, 4588 }
 */
function acceptedGroupIds(groups) {
  if (groups === undefined || groups === null) return _postureGroupIds();
  return _explicitGroupIds(groups, "b.pqcGate.acceptedGroupIds");
}

/**
 * @primitive b.pqcGate.clientHelloHasPQC
 * @signature b.pqcGate.clientHelloHasPQC(buf, opts?)
 * @since     0.1.77
 * @status    stable
 * @compliance soc2
 * @related   b.pqcGate.create, b.pqcGate.acceptedGroupIds
 *
 * Does this buffer hold a TLS ClientHello whose supported_versions extension
 * lists TLS 1.3 and whose supported_groups extension names a post-quantum
 * group the listener offers? Answers a boolean, and answers false for
 * anything it cannot read as a ClientHello, including a record that is
 * truncated, one that is not a handshake record, one whose length fields
 * point past the bytes present, one with no supported_versions extension
 * and one that carries either extension twice.
 *
 * The groups it counts are `b.pqcGate.acceptedGroupIds(opts.groups)`: by
 * default the post-quantum groups the live `b.network.tls` server posture
 * lists ahead of its classical groups. A `groups` value that
 * `acceptedGroupIds` refuses throws `TypeError`.
 *
 * @opts
 *   groups: string|string[],   // the listener's OpenSSL group string; default the b.network.tls server posture
 *
 * @example
 *   var b = require("@blamejs/core");
 *   b.pqcGate.clientHelloHasPQC(Buffer.alloc(0));   // → false
 */
function clientHelloHasPQC(buf, opts) {
  var groups;
  if (opts !== undefined && opts !== null) {
    validateOpts(opts, ["groups"], "b.pqcGate.clientHelloHasPQC");
    groups = opts.groups;
  }
  return _clientHelloOffers(buf, acceptedGroupIds(groups));
}

function _clientHelloOffers(buf, accepted) {
  if (!buf || buf.length < 44) return false;

  if (buf[0] !== 0x16) return false;

  var recordLen = buf.readUInt16BE(3);
  var recordEnd = Math.min(5 + recordLen, buf.length);

  if (buf.length < 10) return false;
  if (buf[5] !== 0x01) return false;

  var offset = 9 + 2 + C.BYTES.bytes(32);
  if (offset + 1 > recordEnd) return false;

  var sessionIdLen = buf[offset];
  offset += 1 + sessionIdLen;
  if (offset + 2 > recordEnd) return false;

  var cipherSuitesLen = buf.readUInt16BE(offset);
  offset += 2 + cipherSuitesLen;
  if (offset + 1 > recordEnd) return false;

  var compLen = buf[offset];
  offset += 1 + compLen;
  if (offset + 2 > recordEnd) return false;

  var extensionsLen = buf.readUInt16BE(offset);
  offset += 2;
  var extensionsEnd = Math.min(offset + extensionsLen, recordEnd);

  var offersGroup = null;
  var offersTls13 = null;
  while (offset + 4 <= extensionsEnd) {
    var extType = buf.readUInt16BE(offset);
    var extLen  = buf.readUInt16BE(offset + 2);
    offset += 4;
    if (offset + extLen > extensionsEnd) return false;

    if (extType === EXT_SUPPORTED_GROUPS) {
      if (offersGroup !== null) return false;
      offersGroup = _groupListHas(buf, offset, extLen, accepted);
    } else if (extType === EXT_SUPPORTED_VERSIONS) {
      if (offersTls13 !== null) return false;
      offersTls13 = _versionListHasTls13(buf, offset, extLen);
    }
    offset += extLen;
  }
  return offersGroup === true && offersTls13 === true;
}

function _groupListHas(buf, offset, extLen, accepted) {
  if (extLen < 2 || buf.readUInt16BE(offset) !== extLen - 2) return false;
  var groupsEnd = offset + extLen;
  for (var groupsOffset = offset + 2; groupsOffset + 2 <= groupsEnd; groupsOffset += 2) {
    if (accepted.has(buf.readUInt16BE(groupsOffset))) return true;
  }
  return false;
}

function _versionListHasTls13(buf, offset, extLen) {
  if (extLen < 1 || buf[offset] !== extLen - 1) return false;
  var versionsEnd = offset + extLen;
  for (var versionsOffset = offset + 1; versionsOffset + 2 <= versionsEnd; versionsOffset += 2) {
    if (buf.readUInt16BE(versionsOffset) === TLS13_VERSION) return true;
  }
  return false;
}

function _checkedBypass(value) {
  if (value === undefined || value === null) return DEFAULT_BYPASS.slice();
  if (!Array.isArray(value)) {
    throw new TypeError("pqc-gate: opts.bypass must be an array of IP addresses or CIDRs; got " + typeof value);
  }
  for (var i = 0; i < value.length; i++) {
    var entry = value[i];
    var problem = (typeof entry === "string" && entry.indexOf("/") === -1 &&
                   net.isIP(ipUtils.dialHost(entry)) === 0)
      ? "is not an IP address or a CIDR"
      : ssrfGuard._listEntryProblem(entry);
    if (problem !== null) {
      throw new TypeError("pqc-gate: opts.bypass[" + i + "] (" + JSON.stringify(entry) + ") " + problem);
    }
  }
  return value.map(ssrfGuard._canonicalListEntry);
}

function _isBypassed(remoteAddr, bypass) {
  if (!remoteAddr) return false;
  for (var i = 0; i < bypass.length; i++) {
    var matched = bypass[i].indexOf("/") !== -1
      ? ssrfGuard._listMatches([bypass[i]], remoteAddr, false)
      : ssrfGuard._sameAddress(bypass[i], remoteAddr);
    if (matched) return true;
  }
  return false;
}

function _logVia(log, level, msg, fields) {
  if (log && typeof log[level] === "function") {
    try { log[level](msg, fields); } catch (_e) { /* logger best-effort */ }
    return;
  }
  var line = msg + (fields ? " " + JSON.stringify(fields) : "");
  if (level === "error" || level === "fatal" || level === "warn") {
    DEFAULT_LOG.warn(line);
  } else {
    DEFAULT_LOG(line);
  }
}

/**
 * @primitive b.pqcGate.create
 * @signature b.pqcGate.create(opts)
 * @since     0.1.77
 * @status    stable
 * @compliance soc2
 * @related   b.pqcGate.clientHelloHasPQC, b.network.tls.outboundPosture
 *
 * Build the gate as a `node:net` server. It is not listening yet: the
 * caller calls `listen` on it, on the port the world reaches, and points
 * `internalPort` at the TLS listener behind it.
 *
 * A connection whose ClientHello offers TLS 1.3 and names a post-quantum
 * group the internal listener offers is piped to it with the bytes already
 * read written first, so the listener sees the whole handshake. Any other
 * is written a TLS handshake-failure alert and destroyed, which is what a
 * TLS client expects rather than a bare close.
 *
 * The internal listener must be able to negotiate TLS 1.3. One whose
 * `maxVersion` is below "TLSv1.3", or whose `secureProtocol` pins an older
 * version, negotiates TLS 1.2 with classical ECDHE with a client the gate
 * passed, and the gate cannot detect that configuration.
 *
 * The listener's groups are `groups` when given, and otherwise the live
 * `b.network.tls.serverKeyAgreementGroups()`, read per connection; see
 * `b.pqcGate.acceptedGroupIds`. Without `groups`, the listener's
 * `ecdhCurve` must be `b.network.tls.serverKeyAgreementGroups()`, which is
 * what `b.network.tls.applyToContext({ base })` writes when `base` carries
 * no `ecdhCurve` or `groups`, and what `b.router`'s `listen()` writes when
 * `tlsOptions` carries no `ecdhCurve`. Pass `groups` when the listener takes
 * its groups from anywhere else, as the same OpenSSL group string. For a
 * `b.router` listener given its own `tlsOptions.ecdhCurve`, that string is
 * the returned server's `keyAgreementGroups`:
 * `groups: server.keyAgreementGroups`. Without it the gate admits a client
 * that offers a post-quantum group the posture ranks first, and a listener
 * whose `ecdhCurve` puts a classical group first negotiates the classical
 * group with it. The listener must list each post-quantum
 * group in a tuple ahead of every classical group ("X25519MLKEM768/X25519",
 * not "X25519MLKEM768:X25519"), and a `groups` value that does not, or that
 * `acceptedGroupIds` otherwise refuses, throws `TypeError`.
 *
 * A peer whose address is in `bypass` is piped through without the check,
 * and the default list is the loopback addresses. An entry is an IP address
 * or a CIDR (`10.0.0.0/8`). Entries and peers are compared in their
 * canonical form, so the entry `10.0.0.5` also bypasses the peer
 * `::ffff:10.0.0.5` that a dual-stack listener reports, and
 * `::ffff:10.0.0.0/104` covers the peer `10.0.0.5`. A `bypass` that is not
 * an array, or an entry that is not an IP address or a well-formed CIDR
 * (`localhost`, `10.0.0.0/33`, `10.0.0/8`), throws `TypeError`. A connection that sends nothing
 * within `clientHelloTimeoutMs`, or more than `maxClientHelloBytes` before
 * a complete ClientHello, is dropped.
 *
 * @opts
 *   internalPort:         number,    // the TLS listener's port; required, 1-65535
 *   internalHost:         string,    // its host; an IPv6 address bare or in brackets; default "127.0.0.1"; an empty value, brackets around anything but an IPv6 address, or a non-string throws TypeError
 *   groups:               string|string[], // the listener's OpenSSL group string; default the b.network.tls server posture
 *   bypass:               string[],  // IP addresses or CIDRs exempt from the check; default loopback
 *   clientHelloTimeoutMs: number,    // wait for the ClientHello; default 5000
 *   maxClientHelloBytes:  number,    // ceiling on what is read; default 16384
 *   log:                  object,    // logger for refusals
 *
 * @example
 *   var b = require("@blamejs/core");
 *   var gate = b.pqcGate.create({ internalPort: 8443 });
 *   gate.listen(443);
 */
function create(opts) {
  opts = opts || {};
  validateOpts(opts, [
    "internalPort", "internalHost", "groups", "bypass",
    "clientHelloTimeoutMs", "maxClientHelloBytes", "log",
    "_connect", "_server", "_setTimeout", "_clearTimeout",
  ], "b.pqcGate");
  var internalPort = opts.internalPort;
  if (typeof internalPort !== "number" || internalPort < 1 || internalPort > 65535) {
    throw new Error("pqc-gate: opts.internalPort must be a port number (1-65535)");
  }
  var fixedGroupIds = (opts.groups === undefined || opts.groups === null)
    ? null
    : _explicitGroupIds(opts.groups, "b.pqcGate.create");
  var internalHost = "127.0.0.1";
  if (opts.internalHost !== undefined && opts.internalHost !== null) {
    var bareHost = typeof opts.internalHost === "string" ? ipUtils.dialHost(opts.internalHost) : "";
    if (bareHost.length === 0 || bareHost.indexOf("[") !== -1 || bareHost.indexOf("]") !== -1 ||
        (bareHost !== opts.internalHost && !net.isIPv6(bareHost))) {
      throw new TypeError("pqc-gate: opts.internalHost must be a non-empty hostname or IP address, " +
        "with brackets only around an IPv6 address; got " +
        (typeof opts.internalHost === "string" ? JSON.stringify(opts.internalHost) : typeof opts.internalHost));
    }
    internalHost = bareHost;
  }
  var bypass       = _checkedBypass(opts.bypass);
  if (opts.clientHelloTimeoutMs !== undefined && !numericBounds.isPositiveFiniteInt(opts.clientHelloTimeoutMs)) {
    throw new Error("pqc-gate: clientHelloTimeoutMs must be a positive finite integer; got " +
      numericBounds.shape(opts.clientHelloTimeoutMs));
  }
  var clientHelloTimeoutMs = opts.clientHelloTimeoutMs || DEFAULT_CLIENTHELLO_TIMEOUT_MS;
  if (opts.maxClientHelloBytes !== undefined && !numericBounds.isPositiveFiniteInt(opts.maxClientHelloBytes)) {
    throw new Error("pqc-gate: maxClientHelloBytes must be a positive finite integer; got " +
      numericBounds.shape(opts.maxClientHelloBytes));
  }
  var maxClientHelloBytes  = opts.maxClientHelloBytes || DEFAULT_MAX_CLIENTHELLO_BYTES;
  var log = opts.log || null;

  var connectFn = opts._connect || function (cOpts, cb) { return net.createConnection(cOpts, cb); };
  var serverFn  = opts._server  || function (sOpts, cb) { return net.createServer(sOpts, cb); };
  var setTimeoutFn  = opts._setTimeout  || setTimeout;
  var clearTimeoutFn = opts._clearTimeout || clearTimeout;

  function pipeToInternal(socket, prependData) {
    var internal = connectFn({ port: internalPort, host: internalHost }, function () {
      if (prependData) internal.write(prependData);
      socket.pipe(internal);
      internal.pipe(socket);
      socket.resume();
    });
    internal.on("error", function () { socket.destroy(); });
    socket.on("error",   function () { internal.destroy(); });
    internal.on("close", function () { socket.destroy(); });
    socket.on("close",   function () { internal.destroy(); });
  }

  function _onConnection(socket) {
    var clientIp = socket.remoteAddress || "";

    if (_isBypassed(clientIp, bypass)) {
      pipeToInternal(socket);
      return;
    }

    var chunks = [];
    var totalLen = 0;
    var resolved = false;

    var timeout = setTimeoutFn(function () {
      if (resolved) return;
      resolved = true;
      _logVia(log, "warn", "ClientHello timeout", { ip: clientIp });
      try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
    }, clientHelloTimeoutMs);

    socket.on("data", function onData(chunk) {
      if (resolved) return;
      chunks.push(chunk);
      totalLen += chunk.length;

      if (totalLen > maxClientHelloBytes) {
        resolved = true;
        try { clearTimeoutFn(timeout); } catch (_e) { /* timer may already have fired */ }
        _logVia(log, "warn", "ClientHello too large", { ip: clientIp, size: totalLen });
        try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
        return;
      }

      if (totalLen >= 1 && chunks[0][0] !== 0x16) {
        resolved = true;
        try { clearTimeoutFn(timeout); } catch (_e) { /* timer may already have fired */ }
        try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
        return;
      }

      if (totalLen < 5) return;

      // allow:handrolled-buffer-collect-bounded-framing — see comment above
      var buf = Buffer.concat(chunks);
      var recordLen = buf.readUInt16BE(3);
      var neededLen = 5 + recordLen;

      if (buf.length < Math.min(neededLen, maxClientHelloBytes)) return;

      resolved = true;
      try { clearTimeoutFn(timeout); } catch (_e) { /* timer may already have fired */ }
      socket.removeListener("data", onData);
      socket.pause();

      if (_clientHelloOffers(buf, fixedGroupIds || _postureGroupIds())) {
        pipeToInternal(socket, buf);
      } else {
        _logVia(log, "warn",
          "connection rejected — no PQC group in ClientHello", { ip: clientIp });
        try {
          socket.write(TLS_ALERT_HANDSHAKE_FAILURE, function () {
            try { socket.destroy(); } catch (_e) { /* socket may already be torn down */ }
          });
        } catch (_e) {
          try { socket.destroy(); } catch (_e2) { /* socket may already be torn down */ }
        }
      }
    });

    socket.on("error", function () {
      resolved = true;
      try { clearTimeoutFn(timeout); } catch (_e) { /* timer may already have fired */ }
    });

    socket.resume();
  }

  return serverFn({ pauseOnConnect: true }, _onConnection);
}

module.exports = {
  create:                       create,
  clientHelloHasPQC:            clientHelloHasPQC,
  acceptedGroupIds:             acceptedGroupIds,
  get PQC_GROUP_IDS() { return _postureGroupIds(); },
  TLS_ALERT_HANDSHAKE_FAILURE:  TLS_ALERT_HANDSHAKE_FAILURE,
  DEFAULT_BYPASS:               DEFAULT_BYPASS,
};

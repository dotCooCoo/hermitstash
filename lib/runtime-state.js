"use strict";
/**
 * Facts only the running process knows, published for anything that reports on
 * it.
 *
 * The admin security panel used to work out whether TLS was serving by looking
 * at the same files server-main.js looks at. That is a copy of a decision, and
 * it drifted: it read the key and not the certificate, so a key mounted ahead of
 * its chain produced a green "TLS: enabled" row on a server that had logged
 * "starting in HTTP mode" and was serving plain HTTP. Deriving it again from
 * more predicates only moves the drift — whether the listener came up also
 * depends on the key loading, which depends on the sealed-key mode, and any
 * re-derivation is a second implementation of that whole rule.
 *
 * So the process records what actually happened, once, at the point it happens,
 * and readers ask. Anything not recorded reads as null, which callers must treat
 * as "not known" rather than false — a panel that reports a protection as off
 * because it was never told is the same failure pointed the other way.
 */

var state = {
  // Did the TLS listener start? Null until boot decides.
  tlsEnabled: null,
  // Is rejectUnauthorized set on that listener — client certs required at the
  // handshake? Only meaningful when tlsEnabled is true.
  hardMtls: null,
};

function set(patch) {
  if (!patch || typeof patch !== "object") return;
  Object.keys(patch).forEach(function (k) {
    if (Object.prototype.hasOwnProperty.call(state, k)) state[k] = patch[k];
  });
}

function get(key) {
  return Object.prototype.hasOwnProperty.call(state, key) ? state[key] : null;
}

function snapshot() {
  return Object.assign({}, state);
}

module.exports = { set: set, get: get, snapshot: snapshot };

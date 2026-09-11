// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var validateOpts = require("../validate-opts");
var { AuthError } = require("../framework-error");

var AAL1 = "AAL1";
var AAL2 = "AAL2";
var AAL3 = "AAL3";

var BANDS_ORDER = [AAL1, AAL2, AAL3];

function _bandRank(band) {
  var idx = BANDS_ORDER.indexOf(band);
  if (idx === -1) return -1;
  return idx;
}

var KNOWN_METHODS = [
  "password", "pin", "totp", "sms", "webauthn", "passkey",
  "hardware", "mtls",
  "uv",
];

function fromMethods(methods) {
  if (!methods || typeof methods !== "object") {
    throw new AuthError("auth-aal/bad-methods",
      "fromMethods: methods must be an object like { password: true, webauthn: true, uv: true }");
  }
  var has = function (m) { return methods[m] === true; };
  if ((has("webauthn") || has("passkey")) && has("uv")) return AAL3;
  if ((has("webauthn") || has("passkey")) && !has("uv")) {
    if (has("password") || has("pin")) return AAL3;
    return AAL2;
  }
  if (has("hardware") && (has("password") || has("pin"))) return AAL3;

  if (has("password") || has("pin")) {
    if (has("totp") || has("sms") || has("hardware") || has("mtls")) return AAL2;
    return AAL1;
  }

  if (has("hardware") || has("mtls")) return AAL1;

  throw new AuthError("auth-aal/no-methods",
    "fromMethods: methods object did not assert any known authenticator " +
    "(known: " + KNOWN_METHODS.join(", ") + ")");
}

function isValidBand(band) {
  return band === AAL1 || band === AAL2 || band === AAL3;
}

function meets(actualBand, requiredBand) {
  if (!isValidBand(actualBand)) return false;
  if (!isValidBand(requiredBand)) return false;
  return _bandRank(actualBand) >= _bandRank(requiredBand);
}

var AMR = Object.freeze({
  PASSWORD:  "pwd",
  PIN:       "pin",
  TOTP:      "otp",
  SMS:       "sms",
  WEBAUTHN:  "hwk",
  PASSKEY:   "passkey",
  HARDWARE:  "hwk",
  MTLS:      "mtls",
});

module.exports = {
  AAL1:         AAL1,
  AAL2:         AAL2,
  AAL3:         AAL3,
  BANDS:        Object.freeze([AAL1, AAL2, AAL3]),
  KNOWN_METHODS: Object.freeze(KNOWN_METHODS),
  AMR:          AMR,
  fromMethods:  fromMethods,
  isValidBand:  isValidBand,
  meets:        meets,
  _validateOpts: validateOpts,
};

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var asn1     = require("../lib/asn1-der");
var expected = require("./_expected");

// asn1-der is the DER byte parser under every untrusted-certificate path in the
// framework -- peer TLS certificates, S/MIME, BIMI VMCs, CMS, ACME and TSA
// responses. readNode / readSequence take raw adversarial bytes and MUST refuse
// malformed input with a typed Asn1Error, never crash with an uncaught
// RangeError / TypeError or blow the stack on deep nesting.
module.exports.fuzz = function (data) {
  var node = null;
  try {
    node = asn1.readNode(data, 0);
  } catch (e) {
    if (!expected.isExpected(e)) throw e;
  }
  try { asn1.readSequence(data); }
  catch (e) { if (!expected.isExpected(e)) throw e; }
  if (node) {
    [asn1.readOid, asn1.readOctetString, asn1.readUnsignedInt, asn1.readBitString].forEach(function (rd) {
      try { rd(node); }
      catch (e) { if (!expected.isExpected(e)) throw e; }
    });
  }
};

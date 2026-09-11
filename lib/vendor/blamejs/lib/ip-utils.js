// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

function expandIpv6Hex(ip) {
  if (typeof ip !== "string") return null;
  var dual = ip.match(/^(.*?):(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);                                    // allow:regex-no-length-cap — dotted-quad has fixed shape; LHS bounded by IPv6 group cap below
  if (dual) {
    if (!isIPv4(dual[2])) return null;
    var v4 = dual[2].split(".").map(Number);
    var hi = (v4[0] << 8) | v4[1];
    var lo = (v4[2] << 8) | v4[3];
    ip = dual[1] + ":" + hi.toString(16) + ":" + lo.toString(16);
  }
  var dblColon = ip.split("::");
  if (dblColon.length > 2) return null;
  var leftGroups  = dblColon[0] === "" ? [] : dblColon[0].split(":");
  var rightGroups = dblColon.length === 2 ? (dblColon[1] === "" ? [] : dblColon[1].split(":")) : [];
  if (dblColon.length === 1 && leftGroups.length !== 8) return null;
  var fillCount = 8 - leftGroups.length - rightGroups.length;
  if (fillCount < 0) return null;
  if (dblColon.length === 2 && fillCount === 0) return null;
  var fill = [];
  for (var f = 0; f < fillCount; f += 1) fill.push("0");
  var groups = leftGroups.concat(fill).concat(rightGroups);
  if (groups.length !== 8) return null;
  var hex = "";
  for (var i = 0; i < 8; i += 1) {
    var g = groups[i];
    if (g.length === 0 || g.length > 4) return null;
    for (var hc = 0; hc < g.length; hc += 1) {
      var cp = g.charCodeAt(hc);
      var isDigit    = cp >= 0x30 && cp <= 0x39;
      var isLowerHex = cp >= 0x61 && cp <= 0x66;
      var isUpperHex = cp >= 0x41 && cp <= 0x46;
      if (!isDigit && !isLowerHex && !isUpperHex) return null;
    }
    hex += g.toLowerCase().padStart(4, "0");
  }
  return hex;
}

function expandIpv6Groups(ip) {
  var hex = expandIpv6Hex(ip);
  if (hex === null) return null;
  var groups = new Array(8);
  for (var i = 0; i < 8; i += 1) {
    groups[i] = parseInt(hex.slice(i * 4, i * 4 + 4), 16);
  }
  return groups;
}

var IPV4_SHAPE_RE = /^\d+\.\d+\.\d+\.\d+$/;                                                              // allow:regex-no-length-cap — anchored + literal-dot shape; caller bounds length
function isIPv4Shape(s) {
  return typeof s === "string" && IPV4_SHAPE_RE.test(s);
}

var IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;       // allow:regex-no-length-cap — anchored + per-octet repeat-cap
function isIPv4(s) {
  return typeof s === "string" && IPV4_RE.test(s);
}

var IPV4_ADDR_LITERAL_RE = /^\[((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})\]$/;  // allow:regex-no-length-cap — anchored + per-octet repeat-cap

var IPV6_TEXT_MAX_LEN = 39;
var IPV6_HEX_RE = /^[0-9a-fA-F:]+$/;                                                                     // allow:regex-no-length-cap — length-bounded by IPV6_TEXT_MAX_LEN in looksLikeIPv6Hex
function looksLikeIPv6Hex(s) {
  return typeof s === "string" && s.length <= IPV6_TEXT_MAX_LEN && IPV6_HEX_RE.test(s);
}

module.exports = {
  expandIpv6Hex:        expandIpv6Hex,
  expandIpv6Groups:     expandIpv6Groups,
  isIPv4Shape:          isIPv4Shape,
  isIPv4:               isIPv4,
  IPV4_RE:              IPV4_RE,
  IPV4_ADDR_LITERAL_RE: IPV4_ADDR_LITERAL_RE,
  looksLikeIPv6Hex:     looksLikeIPv6Hex,
  IPV6_HEX_RE:          IPV6_HEX_RE,
  IPV6_TEXT_MAX_LEN:    IPV6_TEXT_MAX_LEN,
};

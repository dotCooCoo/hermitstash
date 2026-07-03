// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// opts-resolver — single source of truth for "what opts does b.X.Y accept?".
//
// Re-uses the same probe trick the wiki primitive-section validator
// applies in test/validate-primitive-sections.js: call the framework
// function with an unknown opt key, parse the "Allowed keys: …" /
// "Allowed: …" list out of the thrown TypeError. The validator USES
// this to verify wiki opts match lib reality; the section() helper
// USES this to GENERATE the opts block so wiki authors never hand-
// type a key list.
//
// Two consumers, one probe. When the probe fails (positional-args
// signature, async-only validation, custom error shape), the resolver
// returns ok:false with a reason and the caller falls back to inline
// hand-authored opts.

var b = require("@blamejs/core");

function resolveSignaturePath(signature) {
  // "b.module.method(opts)" → ["module", "method"]; strips wrapping
  // <code> markup the wiki sometimes embeds in the heading.
  var match = String(signature).match(/^\s*(?:<code>\s*)?b\.([a-zA-Z0-9_.]+)\s*\(/);
  if (!match) return null;
  var pathParts = match[1].split(".");
  var current = b;
  for (var i = 0; i < pathParts.length; i++) {
    if (current === null || current === undefined) return null;
    current = current[pathParts[i]];
  }
  return typeof current === "function" ? current : null;
}

function probeAllowList(fn) {
  if (typeof fn !== "function") {
    return { ok: false, reason: "not-a-function" };
  }
  var probeKey = "__opts_resolver_probe_" + Date.now() + "_" + Math.random().toString(36).slice(2); // allow:math-random-noncrypto-jitter-sampling — probe-key uniqueness only; never reaches a security boundary
  var probeOpts = {};
  probeOpts[probeKey] = true;
  var thrown = null;
  try {
    var result = fn(probeOpts);
    if (result && typeof result.then === "function") {
      // Async factory — swallow the rejection silently. We only care
      // whether the synchronous prologue threw.
      result.then(function () {}, function () {});
      return { ok: false, reason: "async-no-sync-validate" };
    }
    return { ok: false, reason: "no-throw-on-unknown-key" };
  } catch (e) {
    thrown = e;
  }
  var msg = (thrown && thrown.message) || "";
  var m = msg.match(/Allowed keys?:\s*([^.\n]+)/);
  if (!m) m = msg.match(/Allowed:\s*([^.\n]+)/);
  if (!m) return { ok: false, reason: "no-allow-list-in-error", message: msg };
  var keys = m[1]
    .split(",")
    .map(function (s) { return s.replace(/^\s+|\s+$/g, ""); })
    .filter(Boolean);
  return { ok: true, allowList: keys };
}

// resolve(signature) → { ok, allowList?, reason? }
function resolve(signature) {
  var fn = resolveSignaturePath(signature);
  if (!fn) return { ok: false, reason: "lib-fn-not-resolved" };
  return probeAllowList(fn);
}

module.exports = {
  resolve:               resolve,
  resolveSignaturePath:  resolveSignaturePath,
  probeAllowList:        probeAllowList,
};

"use strict";
/**
 * b.sessionDeviceBinding — two regressions:
 *
 *   (A) IPv6 prefix masking masked the client IP by textual ':'-group slicing
 *       with no canonical normalization, so a `::`-shorthand address and its
 *       fully-expanded equivalent (2001:db8::1 vs 2001:db8:0:0:0:0:0:1), or a
 *       leading-zero-folded group, hashed to DIFFERENT device fingerprints.
 *       A roaming user whose proxy reports the address in a different textual
 *       form on the next request was logged out on a FALSE drift.
 *
 *   (B) #330 — create() refused to construct without a store, so the stateless,
 *       store-free fingerprint() (the soft device-binding building block for
 *       self-validating tokens) was unreachable through create(). The static
 *       b.sessionDeviceBinding.fingerprint(req, opts) and a no-store instance
 *       whose fingerprint() works (while bind/verify throw a clear "no store")
 *       both make it reachable.
 *
 * Run standalone:
 *   node test/layer-0-primitives/session-device-binding-ipv6-canonical-and-no-store.test.js
 * Or via smoke:
 *   node test/smoke.js
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function _memoryStore() {
  var data = new Map();
  return {
    data: data,
    get:  function (k) { return Promise.resolve(data.get(k)); },
    set:  function (k, v) { data.set(k, v); return Promise.resolve(); },
    del:  function (k) { data.delete(k); return Promise.resolve(); },
  };
}

function _req(remoteAddress) {
  return {
    url: "/x",
    method: "GET",
    headers: {
      "user-agent":      "Mozilla/5.0 (Macintosh; Intel)",
      "accept-language": "en-US,en;q=0.9",
      "accept-encoding": "gzip, br",
    },
    socket: { remoteAddress: remoteAddress },
  };
}

// Two textually-different but semantically-IDENTICAL IPv6 forms of the same
// address. A canonical masker must collapse them to one fingerprint bucket.
var IPV6_SHORTHAND = "2001:db8::1";
var IPV6_EXPANDED  = "2001:db8:0:0:0:0:0:1";
// Leading-zero fold: 2001:0db8 vs 2001:db8 are the same group value.
var IPV6_LEADING_ZEROS = "2001:0db8::1";

// (A) Static fingerprint — equivalent IPv6 forms must hash identically.
function testStaticFingerprintCanonicalIpv6() {
  var fpShort    = b.sessionDeviceBinding.fingerprint(_req(IPV6_SHORTHAND));
  var fpExpanded = b.sessionDeviceBinding.fingerprint(_req(IPV6_EXPANDED));
  var fpLeading  = b.sessionDeviceBinding.fingerprint(_req(IPV6_LEADING_ZEROS));
  check("(A) static fp: :: shorthand == fully expanded",
    fpShort.equals(fpExpanded));
  check("(A) static fp: :: shorthand == leading-zero form",
    fpShort.equals(fpLeading));
  // Sanity: a genuinely different /64 still diverges (the mask still binds).
  var fpOther = b.sessionDeviceBinding.fingerprint(_req("2001:db9::1"));
  check("(A) static fp: different /64 still diverges", !fpShort.equals(fpOther));
}

// (A) Real consumer path — bind() with one textual form, verify() with the
// equivalent form, on the shipped instance API. Must NOT drift.
async function testVerifyCanonicalIpv6AcrossForms() {
  var binding = b.sessionDeviceBinding.create({ bindingStore: _memoryStore() });
  var token = "tok_v6";
  await binding.bind(token, _req(IPV6_SHORTHAND));

  var verdict = await binding.verify(token, _req(IPV6_EXPANDED));
  check("(A) verify ok: bind(::) then verify(expanded)", verdict.ok === true);

  var verdict2 = await binding.verify(token, _req(IPV6_LEADING_ZEROS));
  check("(A) verify ok: bind(::) then verify(leading-zeros)", verdict2.ok === true);

  // A different /64 IPv6 still drifts (the prefix check is alive, not disabled).
  var drift = await binding.verify(token, _req("2001:db9::1"));
  check("(A) verify drift: bind(2001:db8::) then verify(2001:db9::)",
    drift.ok === false && drift.reason === "drift");
}

// (A) The documented `ipPrefixBits: { v4: 0, v6: 0 }` skip-the-IP escape hatch
// must still skip masking entirely (so a mobile client that switches networks
// is not logged out).
async function testIpPrefixBitsZeroSkipsIp() {
  var binding = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
    ipPrefixBits: { v4: 0, v6: 0 },
  });
  var token = "tok_skip";
  await binding.bind(token, _req("2001:db8::1"));
  var across = await binding.verify(token, _req("2001:dead:beef::99"));
  check("(A) ipPrefixBits 0/0: unrelated IPv6 still ok (IP skipped)",
    across.ok === true);
  var binding4 = b.sessionDeviceBinding.create({
    bindingStore: _memoryStore(),
    ipPrefixBits: { v4: 0, v6: 0 },
  });
  await binding4.bind("t4", _req("198.51.100.1"));
  var across4 = await binding4.verify("t4", _req("203.0.113.200"));
  check("(A) ipPrefixBits 0/0: unrelated IPv4 still ok (IP skipped)",
    across4.ok === true);
}

// (B) #330 — a no-store create() returns an instance whose fingerprint() is
// usable (pure, no store), while bind/verify/unbind throw a clear "no store
// configured" error. No fabricated no-op store.
async function testNoStoreInstanceFingerprintReachable() {
  var binding = b.sessionDeviceBinding.create({});  // no store, no storeInSession
  check("(B) no-store create() returns an object", binding && typeof binding === "object");

  var fp = binding.fingerprint(_req("2001:db8::1"));
  check("(B) no-store instance fingerprint() returns a 32-byte Buffer",
    Buffer.isBuffer(fp) && fp.length === 32);

  // It must match the static stateless digest for the same shape (one algorithm).
  var staticFp = b.sessionDeviceBinding.fingerprint(_req("2001:db8::1"));
  check("(B) no-store instance fingerprint() == static fingerprint()",
    fp.equals(staticFp));

  var bindThrew = false;
  try { await binding.bind("t", _req("2001:db8::1")); }
  catch (e) { bindThrew = e && e.code === "session-device-binding/no-store"; }
  check("(B) no-store bind() throws no-store error", bindThrew);

  var verifyThrew = false;
  try { await binding.verify("t", _req("2001:db8::1")); }
  catch (e) { verifyThrew = e && e.code === "session-device-binding/no-store"; }
  check("(B) no-store verify() throws no-store error", verifyThrew);

  var unbindThrew = false;
  try { await binding.unbind("t"); }
  catch (e) { unbindThrew = e && e.code === "session-device-binding/no-store"; }
  check("(B) no-store unbind() throws no-store error", unbindThrew);
}

// (B) #330 — the static stateless entry point works with no create() at all.
function testStaticFingerprintNoStore() {
  check("(B) b.sessionDeviceBinding.fingerprint is a function",
    typeof b.sessionDeviceBinding.fingerprint === "function");
  var fp = b.sessionDeviceBinding.fingerprint(_req("203.0.113.7"));
  check("(B) static fingerprint() returns a 32-byte Buffer with no store",
    Buffer.isBuffer(fp) && fp.length === 32);
}

// Codex P2 (#362): routing the IP mask through requestHelpers.ipPrefix must
// PRESERVE the configured prefix width, not silently force the helper's bare
// /24 + /64 default. The device-binding IPv6 default is /48; a client roaming
// within its /48 allocation but across a different /64 must NOT drift. (RED
// when ipPrefix ignores the width and buckets at /64.)
async function testConfiguredV6PrefixWidthPreserved() {
  // Default instance (v6 = /48): same /48, DIFFERENT /64 -> same fingerprint.
  var inst = b.sessionDeviceBinding.create({ bindingStore: _memoryStore() });
  var fpA = inst.fingerprint(_req("2001:db8:0:1::5"));
  var fpB = inst.fingerprint(_req("2001:db8:0:2::9"));     // same /48, different /64
  check("(P2) default v6=/48: same /48 different /64 -> same fp (not /64)", fpA.equals(fpB));
  var fpC = inst.fingerprint(_req("2001:db8:1::5"));        // different /48
  check("(P2) default v6=/48: different /48 still diverges", !fpA.equals(fpC));

  // Configured wider bucket (v6 = /32): same /32, different /48 -> same fp.
  var wide = b.sessionDeviceBinding.create({ bindingStore: _memoryStore(), ipPrefixBits: { v6: 32 } });
  var wA = wide.fingerprint(_req("2001:db8:1::1"));
  var wB = wide.fingerprint(_req("2001:db8:99::1"));        // same /32, different /48
  check("(P2) configured v6=/32: same /32 different /48 -> same fp (width honored)", wA.equals(wB));

  // Configured tighter bucket (v6 = /64): same /48 different /64 -> DIVERGES.
  var tight = b.sessionDeviceBinding.create({ bindingStore: _memoryStore(), ipPrefixBits: { v6: 64 } });
  var tA = tight.fingerprint(_req("2001:db8:0:1::5"));
  var tB = tight.fingerprint(_req("2001:db8:0:2::9"));      // same /48, different /64
  check("(P2) configured v6=/64: same /48 different /64 -> diverges (width honored)", !tA.equals(tB));
}

async function run() {
  testStaticFingerprintCanonicalIpv6();
  await testVerifyCanonicalIpv6AcrossForms();
  await testIpPrefixBitsZeroSkipsIp();
  await testConfiguredV6PrefixWidthPreserved();
  await testNoStoreInstanceFingerprintReachable();
  testStaticFingerprintNoStore();
}

if (require.main === module) {
  run().then(function () {
    console.log("OK session-device-binding-ipv6-canonical-and-no-store — "
      + helpers.getChecks() + " checks");
  }).catch(function (e) {
    console.error("FAIL:", e && e.stack || e);
    process.exit(1);
  });
}

module.exports = { run: run };

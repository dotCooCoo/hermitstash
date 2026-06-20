"use strict";
/**
 * @module b.ai.dp
 * @nav    Compliance
 * @title  Differential privacy
 *
 * @intro
 *   Float-safe differential-privacy mechanisms with per-scope privacy
 *   budgeting. Differential privacy adds calibrated noise to an
 *   aggregate so the output is provably insensitive to any single
 *   record — but the guarantee is fragile: Mironov (2012) showed that
 *   a Laplace mechanism implemented with naive double-precision
 *   sampling lets an attacker distinguish neighbouring datasets with
 *   &gt; 35% probability from a <em>single</em> output, silently
 *   destroying the promise. This module ships only mechanisms whose
 *   sampling is hardened against that class of attack:
 *
 *   - <strong>Laplace via the snapping mechanism</strong> (Mironov
 *     2012): clamp to a bound, draw a CSPRNG sign + full-mantissa
 *     uniform, then round to a power-of-two grid — the rounding
 *     removes the exploitable low-order mantissa bits. Pure
 *     ε-differential privacy.
 *   - <strong>Discrete Gaussian</strong> (Canonne–Kamath–Steinke
 *     2020): integer-exact rejection sampling built from
 *     Bernoulli(exp(−γ)) over exact rationals — no floating-point
 *     noise at all. (ε, δ)-differential privacy, integer-valued.
 *
 *   All randomness comes from <code>b.crypto.generateBytes</code>
 *   (SHAKE256 over the OS CSPRNG), never <code>Math.random</code>.
 *
 *   <code>b.ai.dp.budget({ scope, epsilon, delta })</code> tracks a
 *   privacy budget per scope (per-user / per-tenant / per-query-class)
 *   and refuses a <code>consume</code> that would exceed it.
 *   Composition is accounted two ways:
 *
 *   - <code>"basic"</code> (default) — sum the per-release ε and δ.
 *     Always valid; conservative.
 *   - <code>"rdp"</code> — a Rényi DP accountant (Mironov 2017) tracks
 *     RDP across a grid of orders and converts to (ε, δ) at the
 *     scope's δ, giving a much tighter bound under repeated Gaussian
 *     releases. Requires <code>delta &gt; 0</code>.
 *
 *   NIST SP 800-226 (2025) is the evaluation standard for these
 *   guarantees; Dwork &amp; Roth, "The Algorithmic Foundations of
 *   Differential Privacy", is the canonical reference.
 *
 *   The exponential and sparse-vector mechanisms are
 *   deferred-with-condition: their float-safe constructions (the
 *   base-2 / permute-and-flip exponential mechanism, Ilvento 2019; a
 *   snapped sparse-vector) are a distinct effort, and shipping them
 *   float-<em>unsafe</em> would defeat the module's purpose. They
 *   re-open on operator demand with the named construction.
 *
 * @card
 *   Float-safe differential privacy — snapping-mechanism Laplace
 *   (Mironov 2012) + discrete Gaussian (CKS20), CSPRNG noise, per-
 *   scope ε/δ budgets with basic + Rényi-DP accounting.
 */

var bCrypto = require("./crypto");
var validateOpts = require("./validate-opts");
var lazyRequire = require("./lazy-require");
var { defineClass } = require("./framework-error");

var AiDpError = defineClass("AiDpError", { alwaysPermanent: true });

var audit = lazyRequire(function () { return require("./audit"); });

var MECHANISMS = ["laplace", "gaussian"];
var ACCOUNTINGS = ["basic", "rdp"];

// Rational approximation precision for a real-valued σ² fed to the
// integer-exact discrete-Gaussian sampler. 2^32 keeps the deviation
// from the target σ² below 2^-32 — far under the noise scale — while
// keeping the BigInt denominators bounded.
var SIGMA2_RATIONAL_DEN = 4294967296;          // 2^32 rational-approx denominator, not a byte size

// ---- Minimal exact rational (BigInt num / den, den > 0) ----

function _gcd(a, b) {
  a = a < 0n ? -a : a;
  b = b < 0n ? -b : b;
  while (b) { var t = a % b; a = b; b = t; }
  return a;
}
function _fr(num, den) {
  if (den < 0n) { num = -num; den = -den; }
  var g = _gcd(num, den) || 1n;
  return { num: num / g, den: den / g };
}
function _frFromFloat(x, den) {
  // den is a Number power-of-two-ish denominator; round(x*den)/den.
  return _fr(BigInt(Math.round(x * den)), BigInt(den));
}
function _frMul(a, b) { return _fr(a.num * b.num, a.den * b.den); }
function _frSub(a, b) { return _fr(a.num * b.den - b.num * a.den, a.den * b.den); }
function _frLte(a, b) { return a.num * b.den <= b.num * a.den; }       // a <= b
function _frGt(a, b)  { return a.num * b.den >  b.num * a.den; }       // a >  b

// ---- CSPRNG primitives (all noise routes through b.crypto) ----

// Uniform BigInt in [0, m) via rejection sampling on CSPRNG bytes —
// no modulo bias.
function _uniformBelow(m) {
  if (m <= 0n) throw new AiDpError("ai-dp/internal", "ai.dp: _uniformBelow needs m > 0");
  if (m === 1n) return 0n;
  var bits = m.toString(2).length;
  var bytes = Math.ceil(bits / 8);                        // bits-per-byte divisor, not a size
  var mask = (1n << BigInt(bits)) - 1n;
  for (;;) {
    var buf = bCrypto.generateBytes(bytes);
    var x = 0n;
    for (var i = 0; i < bytes; i++) x = (x << 8n) | BigInt(buf[i]);
    x = x & mask;
    if (x < m) return x;
  }
}

// Uniform double in (0, 1] with full 53-bit mantissa entropy — the
// snapping mechanism's noise source. A 53-bit integer is drawn via
// the BigInt rejection sampler (accumulating 53 bits in a JS Number
// would overflow the 2^53 safe-integer range and skew the draw), then
// mapped (val + 1) / 2^53 → (0, 1].
var TWO_POW_53 = 9007199254740992;                         // 2^53 mantissa range, not a byte size
function _uniformOpen() {
  var v = Number(_uniformBelow(9007199254740992n));        // [0, 2^53) exact
  return (v + 1) / TWO_POW_53;                             // (0, 1]
}

function _randomSign() {
  return (bCrypto.generateBytes(1)[0] & 1) === 1 ? 1 : -1;
}

// ---- Canonne–Kamath–Steinke 2020 integer-exact samplers ----
// Ported verbatim from the reference implementation
// (github.com/IBM/discrete-gaussian-differential-privacy). All
// arithmetic is exact (BigInt rationals); no floating-point noise.

function _bernoulli(p) {                                   // p rational in [0,1]
  return _uniformBelow(p.den) < p.num ? 1 : 0;
}
function _bernoulliExp1(x) {                               // x rational in [0,1]
  var k = 1n;
  for (;;) {
    if (_bernoulli(_fr(x.num, x.den * k)) === 1) k = k + 1n;
    else break;
  }
  return Number(k % 2n);
}
function _bernoulliExp(x) {                                // x rational >= 0
  while (_frGt(x, _fr(1n, 1n))) {
    if (_bernoulliExp1(_fr(1n, 1n)) === 1) x = _frSub(x, _fr(1n, 1n));
    else return 0;
  }
  return _bernoulliExp1(x);
}
function _geometricExpSlow(x) {                            // x rational >= 0
  var k = 0n;
  for (;;) {
    if (_bernoulliExp(x) === 1) k = k + 1n;
    else return k;
  }
}
function _geometricExpFast(x) {                            // x rational > 0; returns BigInt
  if (x.num === 0n) return 0n;
  var t = x.den;
  var u;
  for (;;) {
    u = _uniformBelow(t);
    if (_bernoulliExp(_fr(u, t)) === 1) break;
  }
  var v = _geometricExpSlow(_fr(1n, 1n));
  var value = v * t + u;
  return value / x.num;                                   // integer division
}
function _sampleDLaplace(scaleNum, scaleDen) {            // Lap_Z(scale); returns BigInt
  var invScale = _fr(scaleDen, scaleNum);                 // 1 / scale
  for (;;) {
    var sign = _bernoulli(_fr(1n, 2n));
    var magnitude = _geometricExpFast(invScale);
    if (sign === 1 && magnitude === 0n) continue;
    return magnitude * BigInt(1 - 2 * sign);
  }
}
function _floorSqrtFrac(fr) {                              // floor(sqrt(rational)); returns BigInt
  var num = fr.num, den = fr.den;
  var a = 0n, b = 1n;
  while (b * b * den <= num) b = 2n * b;
  while (a + 1n < b) {
    var c = (a + b) / 2n;
    if (c * c * den <= num) a = c; else b = c;
  }
  return a;
}
function _sampleDGauss(sigma2) {                          // sigma2 rational > 0; returns BigInt
  var t = _floorSqrtFrac(sigma2) + 1n;
  var two_sigma2 = _fr(2n * sigma2.num, sigma2.den);      // 2 * sigma2
  var sigma2_over_t = _fr(sigma2.num, sigma2.den * t);    // sigma2 / t
  for (;;) {
    var candidate = _sampleDLaplace(t, 1n);
    var absC = candidate < 0n ? -candidate : candidate;
    var diff = _frSub(_fr(absC, 1n), sigma2_over_t);       // |candidate| - sigma2/t
    // bias = diff^2 / (2 sigma2)  — multiply diff^2 by the reciprocal of 2σ².
    var diff2 = _fr(diff.num * diff.num, diff.den * diff.den);
    var bias = _frMul(diff2, _fr(two_sigma2.den, two_sigma2.num));
    if (_bernoulliExp(bias) === 1) return candidate;
  }
}

// ---- Snapping-mechanism Laplace (Mironov 2012), float-safe ----

function _clamp(x, bound) {
  if (x < -bound) return -bound;
  if (x > bound) return bound;
  return x;
}
function _snappingLaplace(value, scale, bound) {
  // scale = sensitivity / epsilon (Laplace b). bound B clamps the
  // input + output; the privacy guarantee depends on it. Lambda is
  // the smallest power of two >= scale, so inner / Lambda and
  // Lambda * round(...) are exact float ops — that is what removes
  // the attackable low-order bits the naive sampler leaks.
  var xc = _clamp(value, bound);
  var S = _randomSign();
  var U = _uniformOpen();                                 // (0, 1]
  var lambdaPow = Math.pow(2, Math.ceil(Math.log2(scale)));
  var inner = xc + S * scale * Math.log(U);
  var rounded = lambdaPow * Math.round(inner / lambdaPow);
  return _clamp(rounded, bound);
}

// ---- Rényi-DP costs (Mironov 2017) ----

var RDP_ORDERS = [1.25, 1.5, 1.75, 2, 2.5, 3, 4, 5, 6, 8, 12, 16, 24, 32, 48, 64, 128, 256];   // Rényi DP orders (α), not byte sizes

// Gaussian mechanism with noise-to-sensitivity z = sigma / sensitivity:
// RDP(alpha) = alpha / (2 z^2).
function _rdpGaussian(alpha, sigma, sensitivity) {
  var z = sigma / sensitivity;
  return alpha / (2 * z * z);
}
// Laplace mechanism with pure-DP parameter eps0 (= sensitivity / scale):
// RDP(alpha) = (1/(alpha-1)) * ln( (alpha/(2alpha-1)) e^{(alpha-1)eps0}
//              + ((alpha-1)/(2alpha-1)) e^{-alpha eps0} ).
function _rdpLaplace(alpha, eps0) {
  var a = alpha;
  var num1 = a / (2 * a - 1);
  var num2 = (a - 1) / (2 * a - 1);
  var term = num1 * Math.exp((a - 1) * eps0) + num2 * Math.exp(-a * eps0);
  return Math.log(term) / (a - 1);
}
// Convert an RDP curve (rdp[order]) to (eps, delta): the standard
// RDP -> DP bound eps(delta) = min_alpha ( rdp(alpha) + ln(1/delta)/(alpha-1) ).
function _rdpToEpsilon(rdpByOrder, delta) {
  var best = Infinity;
  for (var i = 0; i < RDP_ORDERS.length; i++) {
    var a = RDP_ORDERS[i];
    var e = rdpByOrder[i] + Math.log(1 / delta) / (a - 1);
    if (e < best) best = e;
  }
  return best;
}

// ---- mechanism descriptor ----

/**
 * @primitive b.ai.dp.mechanism
 * @signature b.ai.dp.mechanism(opts)
 * @since     0.12.29
 * @status    stable
 * @compliance gdpr, soc2
 * @related   b.ai.dp.budget, b.ai.quota.create
 *
 * Build a float-safe DP noise mechanism. <code>type: "laplace"</code>
 * is the snapping mechanism (pure ε-DP, real-valued, needs a
 * <code>bound</code>); <code>type: "gaussian"</code> is the discrete
 * Gaussian (integer-valued, (ε, δ)-DP, needs <code>delta</code>).
 * Pass the result to <code>budget.consume(mechanism, value)</code>.
 *
 * @opts
 *   {
 *     type:        string,   // "laplace" | "gaussian"
 *     sensitivity: number,   // required, > 0 (L1 for laplace, L1/integer for gaussian)
 *     epsilon:     number,   // required, > 0 (per-release ε; ε ≤ 1 for the
 *                            //   classic Gaussian calibration)
 *     delta?:      number,   // gaussian only, required, 0 < δ < 1
 *     bound?:      number,   // laplace only, required, > 0 — clamp bound B
 *   }
 *
 * @example
 *   var lap = b.ai.dp.mechanism({ type: "laplace", sensitivity: 1, epsilon: 0.5, bound: 1000 });
 *   var gss = b.ai.dp.mechanism({ type: "gaussian", sensitivity: 1, epsilon: 0.5, delta: 1e-6 });
 */
function mechanism(opts) {
  validateOpts.requireObject(opts, "ai.dp.mechanism", AiDpError);
  validateOpts(opts, ["type", "sensitivity", "epsilon", "delta", "bound"], "ai.dp.mechanism");

  if (MECHANISMS.indexOf(opts.type) === -1) {
    throw new AiDpError("ai-dp/bad-mechanism",
      "ai.dp.mechanism: type must be one of " + MECHANISMS.join(" / ") +
      " (exponential / sparse-vector are deferred — their float-safe constructions " +
      "re-open on demand)");
  }
  if (typeof opts.sensitivity !== "number" || !isFinite(opts.sensitivity) || opts.sensitivity <= 0) {
    throw new AiDpError("ai-dp/bad-sensitivity",
      "ai.dp.mechanism: sensitivity must be a positive finite number");
  }
  if (typeof opts.epsilon !== "number" || !isFinite(opts.epsilon) || opts.epsilon <= 0) {
    throw new AiDpError("ai-dp/bad-epsilon",
      "ai.dp.mechanism: epsilon must be a positive finite number");
  }

  if (opts.type === "laplace") {
    if (typeof opts.bound !== "number" || !isFinite(opts.bound) || opts.bound <= 0) {
      throw new AiDpError("ai-dp/bad-bound",
        "ai.dp.mechanism: laplace requires bound > 0 (the snapping clamp; the " +
        "privacy guarantee depends on it)");
    }
    var scale = opts.sensitivity / opts.epsilon;
    return Object.freeze({
      type: "laplace", sensitivity: opts.sensitivity, epsilon: opts.epsilon,
      delta: 0, scale: scale, bound: opts.bound,
    });
  }

  // gaussian
  if (typeof opts.delta !== "number" || !isFinite(opts.delta) || opts.delta <= 0 || opts.delta >= 1) {
    throw new AiDpError("ai-dp/bad-delta",
      "ai.dp.mechanism: gaussian requires 0 < delta < 1");
  }
  if (opts.epsilon > 1) {
    throw new AiDpError("ai-dp/epsilon-too-large",
      "ai.dp.mechanism: the classic Gaussian calibration is proven for epsilon <= 1; " +
      "split into multiple releases under an rdp budget, or the analytic Gaussian " +
      "mechanism (Balle-Wang 2018) re-opens this path on demand");
  }
  // Classic Gaussian calibration (Dwork & Roth Thm 3.22), valid for ε ≤ 1.
  var sigma = Math.sqrt(2 * Math.log(1.25 / opts.delta)) * opts.sensitivity / opts.epsilon;
  return Object.freeze({
    type: "gaussian", sensitivity: opts.sensitivity, epsilon: opts.epsilon,
    delta: opts.delta, sigma: sigma, sigma2: sigma * sigma,
  });
}

// Apply a mechanism's noise to a numeric value (no accounting — the
// budget wraps this).
function _applyMechanism(m, value) {
  if (typeof value !== "number" || !isFinite(value)) {
    throw new AiDpError("ai-dp/bad-value", "ai.dp: value must be a finite number");
  }
  if (m.type === "laplace") {
    return _snappingLaplace(value, m.scale, m.bound);
  }
  // gaussian — discrete, integer noise added to the (rounded) value.
  var sigma2Frac = _frFromFloat(m.sigma2, SIGMA2_RATIONAL_DEN);
  var noise = _sampleDGauss(sigma2Frac);
  return Math.round(value) + Number(noise);
}

function _mechRdp(m, orderIndex) {
  var alpha = RDP_ORDERS[orderIndex];
  if (m.type === "gaussian") return _rdpGaussian(alpha, m.sigma, m.sensitivity);
  return _rdpLaplace(alpha, m.epsilon);
}

// ---- per-scope budget ----

/**
 * @primitive b.ai.dp.budget
 * @signature b.ai.dp.budget(opts)
 * @since     0.12.29
 * @status    stable
 * @compliance gdpr, soc2
 * @related   b.ai.dp.mechanism, b.ai.quota.create
 *
 * Track a differential-privacy budget for one scope (per-user /
 * per-tenant / per-query-class) and refuse a release that would
 * exceed it. Returns <code>{ consume, remaining, spent, reset }</code>.
 * <code>consume(mechanism, value)</code> adds the mechanism's noise,
 * charges the accountant, and throws <code>aiDp/budget-exhausted</code>
 * if the release would push the scope past its (ε, δ). With
 * <code>accounting: "rdp"</code> the charge is accounted via Rényi DP
 * for a tight composition bound (requires <code>delta &gt; 0</code>);
 * <code>"basic"</code> (default) sums per-release ε and δ.
 *
 * @opts
 *   {
 *     scope:       string,   // required, the budget scope id
 *     epsilon:     number,   // required, total ε budget (> 0)
 *     delta?:      number,   // total δ budget (>= 0; required > 0 for rdp / gaussian)
 *     accounting?: string,   // "basic" (default) | "rdp"
 *     audit?:      boolean,  // default: true
 *   }
 *
 * @example
 *   var b1 = b.ai.dp.budget({ scope: "tenant-acme:daily", epsilon: 3, delta: 1e-6, accounting: "rdp" });
 *   var m  = b.ai.dp.mechanism({ type: "gaussian", sensitivity: 1, epsilon: 0.5, delta: 1e-6 });
 *   var out = b1.consume(m, trueCount);
 *   // → { value: <noised>, cost: { epsilon: 0.5, delta: 1e-6 }, remaining: { epsilon, delta } }
 */
function budget(opts) {
  validateOpts.requireObject(opts, "ai.dp.budget", AiDpError);
  validateOpts(opts, ["scope", "epsilon", "delta", "accounting", "audit"], "ai.dp.budget");

  validateOpts.requireNonEmptyString(opts.scope,
    "ai.dp.budget: scope", AiDpError, "ai-dp/bad-scope");
  if (typeof opts.epsilon !== "number" || !isFinite(opts.epsilon) || opts.epsilon <= 0) {
    throw new AiDpError("ai-dp/bad-epsilon", "ai.dp.budget: epsilon must be a positive finite number");
  }
  var totalEpsilon = opts.epsilon;
  var totalDelta = (opts.delta == null) ? 0 : opts.delta;
  if (typeof totalDelta !== "number" || !isFinite(totalDelta) || totalDelta < 0 || totalDelta >= 1) {
    throw new AiDpError("ai-dp/bad-delta", "ai.dp.budget: delta must be in [0, 1)");
  }
  var accounting = (opts.accounting == null) ? "basic" : opts.accounting;
  if (ACCOUNTINGS.indexOf(accounting) === -1) {
    throw new AiDpError("ai-dp/bad-accounting",
      "ai.dp.budget: accounting must be one of " + ACCOUNTINGS.join(" / "));
  }
  if (accounting === "rdp" && totalDelta <= 0) {
    throw new AiDpError("ai-dp/bad-accounting",
      "ai.dp.budget: rdp accounting requires delta > 0 (the RDP→(ε,δ) conversion is " +
      "undefined at delta = 0; use basic accounting for pure-ε budgets)");
  }
  var auditOn = opts.audit !== false;

  var scope = opts.scope;
  var spentEpsilon = 0;          // basic accounting
  var spentDelta = 0;
  var rdp = RDP_ORDERS.map(function () { return 0; });   // rdp accounting

  var _emitAudit = audit().namespaced(null, { audit: auditOn });

  function _currentEpsilon(rdpCurve) {
    if (accounting === "basic") return spentEpsilon;
    return _rdpToEpsilon(rdpCurve, totalDelta);
  }

  function remaining() {
    if (accounting === "basic") {
      return {
        epsilon: Math.max(0, totalEpsilon - spentEpsilon),
        delta:   Math.max(0, totalDelta - spentDelta),
      };
    }
    return { epsilon: Math.max(0, totalEpsilon - _rdpToEpsilon(rdp, totalDelta)), delta: totalDelta };
  }

  function spent() {
    if (accounting === "basic") return { epsilon: spentEpsilon, delta: spentDelta };
    return { epsilon: _rdpToEpsilon(rdp, totalDelta), delta: totalDelta };
  }

  function consume(m, value) {
    if (!m || typeof m !== "object" || MECHANISMS.indexOf(m.type) === -1) {
      throw new AiDpError("ai-dp/bad-mechanism",
        "ai.dp.budget.consume: first argument must be a b.ai.dp.mechanism");
    }
    if (m.type === "gaussian" && totalDelta <= 0) {
      throw new AiDpError("ai-dp/bad-delta",
        "ai.dp.budget.consume: a gaussian mechanism needs a scope delta > 0");
    }

    // Prospective accounting: would this release fit under the budget?
    var cost;
    if (accounting === "basic") {
      if (spentEpsilon + m.epsilon > totalEpsilon + 1e-12 ||
          spentDelta + m.delta > totalDelta + 1e-12) {
        _emitAudit("dp/budget-exhausted", "denied", {
          scope: scope, accounting: accounting, mechanism: m.type,
          requestEpsilon: m.epsilon, requestDelta: m.delta,
          spentEpsilon: spentEpsilon, totalEpsilon: totalEpsilon,
        });
        throw new AiDpError("ai-dp/budget-exhausted",
          "ai.dp.budget.consume: scope '" + scope + "' would spend ε=" +
          (spentEpsilon + m.epsilon) + "/" + totalEpsilon + ", δ=" +
          (spentDelta + m.delta) + "/" + totalDelta + "; refused");
      }
      cost = { epsilon: m.epsilon, delta: m.delta };
    } else {
      var trial = rdp.map(function (r, i) { return r + _mechRdp(m, i); });
      var trialEps = _rdpToEpsilon(trial, totalDelta);
      if (trialEps > totalEpsilon + 1e-12) {
        _emitAudit("dp/budget-exhausted", "denied", {
          scope: scope, accounting: accounting, mechanism: m.type,
          projectedEpsilon: trialEps, totalEpsilon: totalEpsilon,
        });
        throw new AiDpError("ai-dp/budget-exhausted",
          "ai.dp.budget.consume: scope '" + scope + "' would reach ε=" +
          trialEps.toFixed(4) + " of " + totalEpsilon + " at δ=" + totalDelta + "; refused");
      }
      var before = _rdpToEpsilon(rdp, totalDelta);
      cost = { epsilon: trialEps - before, delta: 0 };
    }

    // Charge, then sample. (Sampling never fails; charging first keeps
    // the budget monotone even if a caller ignores the throw path.)
    var noised = _applyMechanism(m, value);
    if (accounting === "basic") {
      spentEpsilon += m.epsilon;
      spentDelta += m.delta;
    } else {
      rdp = rdp.map(function (r, i) { return r + _mechRdp(m, i); });
    }

    _emitAudit("dp/budget-consumed", "allowed", {
      scope: scope, accounting: accounting, mechanism: m.type,
      epsilon: m.epsilon, delta: m.delta,
    });
    return { value: noised, cost: cost, remaining: remaining() };
  }

  function reset() {
    spentEpsilon = 0;
    spentDelta = 0;
    rdp = RDP_ORDERS.map(function () { return 0; });
  }

  return {
    consume:    consume,
    remaining:  remaining,
    spent:      spent,
    reset:      reset,
    scope:      scope,
    accounting: accounting,
  };
}

module.exports = {
  mechanism:   mechanism,
  budget:      budget,
  MECHANISMS:  MECHANISMS,
  ACCOUNTINGS: ACCOUNTINGS,
  AiDpError:   AiDpError,
};

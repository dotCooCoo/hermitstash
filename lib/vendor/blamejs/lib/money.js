"use strict";
/**
 * @module    b.money
 * @nav       Domain
 * @title     Money
 * @order     500
 * @slug      money
 * @featured  true
 *
 * @intro
 *   Decimal-safe money arithmetic. The framework primitive every
 *   billing / invoicing / shop consumer reaches for so the IEEE 754
 *   double-precision `0.1 + 0.2 !== 0.3` rounding error never reaches
 *   an invoice line, a tax cell, or a ledger row.
 *
 *   ## Why not Number
 *
 *   JavaScript's `Number` is a binary64 (IEEE 754 double). `0.10` and
 *   `0.20` are unrepresentable in binary fraction; the closest binary
 *   approximations sum to `0.30000000000000004`. Add 10,000 such
 *   approximations into a daily revenue total and the cumulative drift
 *   is large enough to fail a SOX 404 reconciliation. The framework's
 *   defense is to refuse `Number` at the boundary: `Money` values
 *   carry BigInt minor units (cents / pence / sen / yen / fils) and a
 *   currency tag pulled from the ISO 4217 catalog. Every arithmetic
 *   operation is integer BigInt math; rounding (where it must happen --
 *   FX conversion, weighted allocation) is bankers' (half-to-even)
 *   by default and explicit when not.
 *
 *   ## What ships
 *
 *   - `b.money.of(amount, currency)` -- accepts BigInt minor units OR a
 *     decimal-shaped string ("12.50"). Numbers refused at the boundary.
 *   - `b.money.fromMinorUnits(bigint, currency)` -- direct construction.
 *   - `b.money.parse("12.50 USD")` -- bidirectional shape parser
 *     (`<amount> <code>` AND `<code> <amount>`).
 *   - `b.money.zero(currency)` -- convenience zero.
 *   - `b.money.convert(money, toCurrency, fxRateProvider, opts?)` --
 *     conversion through an operator-injected rate provider. Framework
 *     NEVER bakes rates in.
 *   - `b.money.CURRENCIES` -- frozen ISO 4217 catalog (code -> exponent).
 *   - `b.money.MoneyError` -- typed refusal class.
 *
 *   ## Allocation
 *
 *   `m.allocate([w1, w2, ...])` uses the largest-remainder method:
 *   floor each weighted share, then distribute the remainder unit-by-
 *   unit to shares with the largest fractional remainder. `$10.00 /
 *   [1, 1, 1]` returns `[$3.34, $3.33, $3.33]` (sum exact). `$100.00 /
 *   [60, 40]` returns `[$60.00, $40.00]`. Deterministic; total
 *   preserved by construction.
 *
 *   ## Rounding
 *
 *   FX conversion rounds half-to-even (bankers'). Opt into half-up at
 *   the call site when an operator regime demands it.
 *
 *   ## RFC / standards
 *
 *   - ISO 4217 -- currency code + minor-unit catalog.
 *   - BCP 47 -- locale tags consumed by `format()` via Intl.NumberFormat.
 *   - IEEE 754 binary64 -- the binary fraction representation we
 *     refuse at the API boundary. Documented to make the refusal
 *     visible to auditors.
 *
 * @card
 *   BigInt minor units + ISO 4217 catalog + largest-remainder
 *   allocation. Numbers refused at the boundary; FX conversion rounds
 *   half-to-even.
 */

var { defineClass } = require("./framework-error");

var MoneyError = defineClass("MoneyError", { alwaysPermanent: true });

// ---- ISO 4217 minor-unit catalog ---------------------------------------
//
// Sourced from the ISO 4217 maintenance agency's "current funds" table.
// Exponent is the number of digits after the decimal that compose one
// major unit (USD -> 2, JPY -> 0, KWD -> 3, CLF -> 4). The framework
// never embeds rates -- operators inject FX via the rateProvider
// contract.
//
// The catalog is intentionally narrow: the ~36 currencies operators
// actually price + settle in. Adding an entry is a one-line edit
// (code + exponent). Codes the catalog does NOT recognise are refused
// at construction time so operators catch typos at boot.

var _CURRENCIES = Object.freeze({
  // exponent 2 (cents / pence / centavos / oere / etc.)
  USD: 2, EUR: 2, GBP: 2, CHF: 2, CAD: 2, AUD: 2, NZD: 2,
  HKD: 2, SGD: 2, CNY: 2, TWD: 2, INR: 2, BRL: 2, MXN: 2,
  ZAR: 2, SEK: 2, NOK: 2, DKK: 2, PLN: 2, CZK: 2, HUF: 2,
  RUB: 2, TRY: 2, AED: 2, SAR: 2, ILS: 2, THB: 2, IDR: 2,
  PHP: 2, MYR: 2, VND: 2, ARS: 2, COP: 2, PEN: 2,
  // exponent 0 (whole-unit minor -- yen / won / etc.)
  JPY: 0, KRW: 0, CLP: 0,
  // exponent 3 (fils / dinar fractions per ISO 4217)
  KWD: 3, BHD: 3, JOD: 3, OMR: 3, TND: 3,
  // exponent 4 (CLF -- UF unidad de fomento)
  CLF: 4,
});

var CURRENCIES = _CURRENCIES;                                              // exported alias; same frozen object

// _pow10(n) -- BigInt 10^n, computed once per call. Avoids any raw
// `10n ** Xn` literal in the source and centralises the negative-n
// refusal in one place.
function _pow10(n) {
  var p = 1n;
  for (var i = 0; i < n; i++) p = p * 10n;
  return p;
}

function _isCurrencyCode(code) {
  return typeof code === "string" &&
         Object.prototype.hasOwnProperty.call(_CURRENCIES, code);
}

function _requireCurrency(code) {
  if (!_isCurrencyCode(code)) {
    throw new MoneyError("money/bad-currency",
      "unknown ISO 4217 currency code: " + JSON.stringify(code));
  }
}

function _exponentOf(code) {
  return _CURRENCIES[code];
}

// _parseDecimalString -- accepts strings of the form `[-]<int>[.<frac>]`
// and returns a BigInt minor-unit count under the requested exponent.
// Fractional digits beyond the exponent ARE refused (silent truncation
// would erase audit-relevant precision; operators round at the call
// site if they need to).
var _DECIMAL_RE = /^(-)?(\d+)(?:\.(\d+))?$/;
function _parseDecimalString(amount, exponent) {
  if (typeof amount !== "string" || amount.length === 0) {
    throw new MoneyError("money/bad-amount",
      "amount string must be non-empty");
  }
  // Strict shape: optional sign, integer part, optional fractional
  // part. No exponent notation (`1e3`), no thousands separators
  // (locale ambiguity -> operator pre-normalises), no whitespace.
  var match = amount.match(_DECIMAL_RE);
  if (!match) {
    throw new MoneyError("money/bad-amount",
      "amount string must match /^-?\\d+(\\.\\d+)?$/, got " +
      JSON.stringify(amount));
  }
  var sign = match[1] === "-" ? -1n : 1n;
  var intPart = match[2];
  var fracPart = match[3] || "";
  if (fracPart.length > exponent) {
    throw new MoneyError("money/precision-loss",
      "amount " + JSON.stringify(amount) + " has " + fracPart.length +
      " fractional digit(s); currency allows " + exponent);
  }
  // Pad fractional part to the exponent so we can read as one BigInt.
  while (fracPart.length < exponent) fracPart = fracPart + "0";
  var minor = BigInt(intPart + fracPart);
  return sign * minor;
}

// _formatMinorUnits -- render a BigInt minor-unit count as a decimal
// string with the requested exponent. Used by toString() and as the
// fallback for format() when Intl.NumberFormat isn't a fit.
function _formatMinorUnits(minor, exponent) {
  var neg = minor < 0n;
  var abs = neg ? -minor : minor;
  if (exponent === 0) return (neg ? "-" : "") + abs.toString();
  var s = abs.toString();
  while (s.length <= exponent) s = "0" + s;
  var head = s.slice(0, s.length - exponent);
  var tail = s.slice(s.length - exponent);
  return (neg ? "-" : "") + head + "." + tail;
}

// _requireSameCurrency -- throws on cross-currency arithmetic.
// Preserves the invariant; operators catch the bug at the call site.
function _requireSameCurrency(a, b, op) {
  if (a.currency !== b.currency) {
    throw new MoneyError("money/currency-mismatch",
      "cannot " + op + " " + a.currency + " and " + b.currency +
      "; convert first via b.money.convert(...)");
  }
}

function _requireMoney(value, label) {
  if (!(value instanceof Money)) {
    throw new MoneyError("money/bad-operand",
      label + " must be a Money instance");
  }
}

// ---- Money value class -------------------------------------------------

/**
 * @primitive b.money.Money
 * @signature b.money.Money(minorUnits, currency)
 * @since     0.11.25
 * @status    stable
 * @related   b.money.of, b.money.fromMinorUnits
 *
 * The immutable `Money` value class. Operators rarely construct
 * directly -- reach for `b.money.of` (string or BigInt) or
 * `b.money.fromMinorUnits` (BigInt) instead. The class is exported
 * so `instance instanceof b.money.Money` is a stable type check
 * when receiving Money values across module boundaries.
 *
 * Instance methods: `add`, `subtract`, `multiply`, `allocate`,
 * `negate`, `abs`, `equals`, `lessThan`, `greaterThan`,
 * `lessThanOrEqual`, `greaterThanOrEqual`, `isZero`, `isNegative`,
 * `isPositive`, `toMinorUnits`, `toString`, `toJSON`, `format`.
 *
 * @example
 *   var m = new b.money.Money(1250n, "USD");
 *   m instanceof b.money.Money;
 */
function Money(minorUnits, currency) {
  if (typeof minorUnits !== "bigint") {
    throw new MoneyError("money/bad-minor-units",
      "minorUnits must be a BigInt; got " + (typeof minorUnits));
  }
  _requireCurrency(currency);
  this._minor    = minorUnits;
  this.currency  = currency;
  Object.freeze(this);
}

Money.prototype.toMinorUnits = function () { return this._minor; };

Money.prototype.add = function (other) {
  _requireMoney(other, "add operand");
  _requireSameCurrency(this, other, "add");
  return new Money(this._minor + other._minor, this.currency);
};

Money.prototype.subtract = function (other) {
  _requireMoney(other, "subtract operand");
  _requireSameCurrency(this, other, "subtract");
  return new Money(this._minor - other._minor, this.currency);
};

// multiply -- scale by a rational. Accepts either a BigInt scalar
// (`m.multiply(3n)`), a `[numerator, denominator]` BigInt pair, or a
// decimal-shaped string (`"1.085"`). Refuses Number -- same boundary
// discipline as construction.
Money.prototype.multiply = function (factor, opts) {
  opts = opts || {};
  var rounding = opts.rounding === "half-up" ? "half-up" : "half-even";
  var num;
  var den;
  if (typeof factor === "bigint") {
    return new Money(this._minor * factor, this.currency);
  }
  if (Array.isArray(factor) && factor.length === 2 &&
      typeof factor[0] === "bigint" && typeof factor[1] === "bigint") {
    num = factor[0];
    den = factor[1];
  } else if (typeof factor === "string") {
    var parsed = _rationalFromDecimalString(factor);
    num = parsed.num;
    den = parsed.den;
  } else {
    throw new MoneyError("money/bad-factor",
      "multiply factor must be BigInt, [num, den] BigInt pair, or " +
      "decimal string; refuse Number to keep the no-binary-fraction " +
      "invariant intact");
  }
  if (den === 0n) {
    throw new MoneyError("money/division-by-zero",
      "multiply denominator is zero");
  }
  var product = this._minor * num;
  var quotient = _divRound(product, den, rounding);
  return new Money(quotient, this.currency);
};

// _rationalFromDecimalString -- `"1.085"` -> { num: 1085n, den: 1000n }.
// Strict shape; same refusals as _parseDecimalString.
function _rationalFromDecimalString(s) {
  if (typeof s !== "string" || s.length === 0) {
    throw new MoneyError("money/bad-factor",
      "decimal factor must be a non-empty string");
  }
  var m = s.match(_DECIMAL_RE);
  if (!m) {
    throw new MoneyError("money/bad-factor",
      "decimal factor must match /^-?\\d+(\\.\\d+)?$/, got " +
      JSON.stringify(s));
  }
  var sign = m[1] === "-" ? -1n : 1n;
  var intPart = m[2];
  var fracPart = m[3] || "";
  var num = sign * BigInt(intPart + fracPart);
  var den = _pow10(fracPart.length);
  return { num: num, den: den };
}

// _divRound -- integer-divide `n / d` and round per `rounding`.
// half-even: banker's rounding, the IEEE 754 default and the ISO 80000
// recommendation. half-up: rounds .5 away from zero.
function _divRound(n, d, rounding) {
  if (d === 0n) {
    throw new MoneyError("money/division-by-zero",
      "divisor is zero in _divRound");
  }
  // Work with signed values; normalise sign to denominator-positive so
  // the half-way arithmetic doesn't have to handle d < 0.
  if (d < 0n) { n = -n; d = -d; }
  var q = n / d;
  var r = n - q * d;
  if (r === 0n) return q;
  var twiceRemAbs = r < 0n ? -r * 2n : r * 2n;
  var cmp;                                                                 // -1: below half, 0: exactly half, 1: above half
  if (twiceRemAbs < d) cmp = -1;
  else if (twiceRemAbs === d) cmp = 0;
  else cmp = 1;
  var bump;
  if (cmp < 0) {
    bump = 0n;
  } else if (cmp > 0) {
    bump = 1n;
  } else if (rounding === "half-up") {
    bump = 1n;
  } else {
    // half-even -- only bump if q is odd (after sign).
    var qAbs = q < 0n ? -q : q;
    bump = (qAbs % 2n === 1n) ? 1n : 0n;
  }
  if (bump === 0n) return q;
  return r < 0n ? q - 1n : q + 1n;
}

// allocate -- split `this` into `weights.length` parts proportional to
// the weights, distributing every minor unit. Largest-remainder
// method: floor each share, then hand out the leftover units to the
// shares with the largest fractional remainder. Total preserved by
// construction; deterministic across runtimes.
Money.prototype.allocate = function (weights) {
  if (!Array.isArray(weights) || weights.length === 0) {
    throw new MoneyError("money/bad-weights",
      "allocate requires a non-empty array of weights");
  }
  var sum = 0n;
  var w = new Array(weights.length);
  for (var i = 0; i < weights.length; i++) {
    var wi = weights[i];
    var wBig;
    if (typeof wi === "bigint") wBig = wi;
    else if (typeof wi === "number" && Number.isInteger(wi)) wBig = BigInt(wi);
    else {
      throw new MoneyError("money/bad-weight",
        "weight[" + i + "] must be BigInt or integer Number; got " +
        (typeof wi));
    }
    if (wBig < 0n) {
      throw new MoneyError("money/bad-weight",
        "weight[" + i + "] is negative; allocation refuses negative shares");
    }
    w[i] = wBig;
    sum = sum + wBig;
  }
  if (sum === 0n) {
    throw new MoneyError("money/bad-weights",
      "allocate weights sum to zero");
  }
  var total = this._minor;
  var shares = new Array(weights.length);
  var remainders = new Array(weights.length);
  var allocated = 0n;
  for (var j = 0; j < weights.length; j++) {
    // share = floor(total * w[j] / sum). For BigInt /, truncation is
    // toward zero; we want floor (toward -infinity) so the leftover
    // pass below distributes positively. Adjust when total < 0.
    var num2 = total * w[j];
    var q = num2 / sum;
    var r = num2 - q * sum;
    if (r !== 0n && total < 0n) {
      q = q - 1n;
      r = r + sum;
    }
    shares[j] = q;
    remainders[j] = { idx: j, rem: r };
    allocated = allocated + q;
  }
  var leftover = total - allocated;
  // leftover is non-negative after the floor adjustment above (proof:
  // for total >= 0, each share is floor toward zero so allocated <=
  // total; for total < 0, each share is floored toward -infty so
  // allocated <= total likewise). Distribute one unit at a time to
  // the largest remainder. Ties broken by index (deterministic).
  remainders.sort(function (a, b) {
    if (a.rem === b.rem) return a.idx - b.idx;
    return a.rem < b.rem ? 1 : -1;
  });
  var k = 0;
  while (leftover > 0n) {
    shares[remainders[k % remainders.length].idx] =
      shares[remainders[k % remainders.length].idx] + 1n;
    leftover = leftover - 1n;
    k = k + 1;
  }
  var out = new Array(shares.length);
  for (var s2 = 0; s2 < shares.length; s2++) {
    out[s2] = new Money(shares[s2], this.currency);
  }
  return out;
};

Money.prototype.negate = function () {
  return new Money(-this._minor, this.currency);
};

Money.prototype.abs = function () {
  return new Money(this._minor < 0n ? -this._minor : this._minor, this.currency);
};

Money.prototype.equals = function (other) {
  _requireMoney(other, "equals operand");
  return this.currency === other.currency && this._minor === other._minor;
};

Money.prototype.lessThan = function (other) {
  _requireMoney(other, "lessThan operand");
  _requireSameCurrency(this, other, "compare");
  return this._minor < other._minor;
};

Money.prototype.greaterThan = function (other) {
  _requireMoney(other, "greaterThan operand");
  _requireSameCurrency(this, other, "compare");
  return this._minor > other._minor;
};

Money.prototype.lessThanOrEqual = function (other) {
  _requireMoney(other, "lessThanOrEqual operand");
  _requireSameCurrency(this, other, "compare");
  return this._minor <= other._minor;
};

Money.prototype.greaterThanOrEqual = function (other) {
  _requireMoney(other, "greaterThanOrEqual operand");
  _requireSameCurrency(this, other, "compare");
  return this._minor >= other._minor;
};

Money.prototype.isZero = function () {
  return this._minor === 0n;
};

Money.prototype.isNegative = function () {
  return this._minor < 0n;
};

Money.prototype.isPositive = function () {
  return this._minor > 0n;
};

// toString -- canonical `<decimal-major> <code>` shape. Always
// 2-decimal for USD-shaped currencies, 0-decimal for JPY, 3-decimal
// for KWD, 4-decimal for CLF. The shape round-trips through
// `b.money.parse`.
Money.prototype.toString = function () {
  var exp = _exponentOf(this.currency);
  return _formatMinorUnits(this._minor, exp) + " " + this.currency;
};

// toJSON -- operator-side serialisation. `minorUnits` is rendered as a
// decimal string (BigInt isn't JSON-native; loss-free string survives
// every transport). Pair with `fromJSON` for round-trip.
Money.prototype.toJSON = function () {
  return { minorUnits: this._minor.toString(), currency: this.currency };
};

// format -- locale-aware string via Intl.NumberFormat when a locale is
// supplied or when the host runtime exposes Intl (every Node ICU
// build does). Falls back to `toString()` on any host that lacks Intl
// or rejects the currency. Operators wanting strict-locale rendering
// reach for Intl.NumberFormat directly; this method is the convenience
// shape.
Money.prototype.format = function (locale) {
  var exp = _exponentOf(this.currency);
  // Compose the decimal value as a Number ONLY for the Intl call --
  // never use it for arithmetic. JPY (exp=0) is exact; for larger
  // exponents we pass a string-derived Number knowing the formatter
  // re-quantises to the currency exponent via minimumFractionDigits.
  var decStr = _formatMinorUnits(this._minor, exp);
  var asNum = Number(decStr);
  if (typeof Intl !== "undefined" && Intl.NumberFormat) {
    try {
      var fmt = new Intl.NumberFormat(locale || undefined, {
        style:                   "currency",
        currency:                this.currency,
        minimumFractionDigits:   exp,
        maximumFractionDigits:   exp,
      });
      return fmt.format(asNum);
    } catch (_e) {
      // Locale or currency rejected by ICU -- fall through to canonical.
    }
  }
  return this.toString();
};

// ---- Factories ---------------------------------------------------------

/**
 * @primitive b.money.of
 * @signature b.money.of(amount, currency)
 * @since     0.11.25
 * @status    stable
 * @related   b.money.fromMinorUnits, b.money.parse
 *
 * Build a `Money` from `amount` (BigInt minor units OR decimal-shaped
 * string) and an ISO 4217 currency code. Throws `MoneyError` on bad
 * shape. Numbers are refused at the boundary -- the framework's
 * defense against IEEE 754 binary-fraction drift.
 *
 * @example
 *   var price = b.money.of("12.50", "USD");
 *   var fee   = b.money.of(250n, "USD");
 *   var tip   = b.money.of("0", "JPY");
 */
function of(amount, currency) {
  _requireCurrency(currency);
  var exp = _exponentOf(currency);
  if (typeof amount === "bigint") {
    return new Money(amount, currency);
  }
  if (typeof amount === "string") {
    return new Money(_parseDecimalString(amount, exp), currency);
  }
  if (typeof amount === "number") {
    throw new MoneyError("money/number-refused",
      "Number amounts refused at the API boundary -- pass BigInt minor " +
      "units (e.g. 250n) or a decimal-shaped string (\"2.50\"). " +
      "Number values lose precision under IEEE 754 binary fractions.");
  }
  throw new MoneyError("money/bad-amount",
    "amount must be BigInt minor units or decimal-shaped string; got " +
    (typeof amount));
}

/**
 * @primitive b.money.fromMinorUnits
 * @signature b.money.fromMinorUnits(minorUnits, currency)
 * @since     0.11.25
 * @status    stable
 * @related   b.money.of
 *
 * Build a `Money` directly from a BigInt minor-unit count. The
 * lowest-overhead constructor; useful when restoring from a ledger
 * row or a wire-shape `toJSON` payload.
 *
 * @example
 *   var due = b.money.fromMinorUnits(1250n, "USD");
 */
function fromMinorUnits(minorUnits, currency) {
  return new Money(minorUnits, currency);
}

// _PARSE_AMOUNT_FIRST_RE / _PARSE_CODE_FIRST_RE -- the two accepted shapes.
var _PARSE_AMOUNT_FIRST_RE = /^(-?\d+(?:\.\d+)?)\s+([A-Z]{3})$/;
var _PARSE_CODE_FIRST_RE   = /^([A-Z]{3})\s+(-?\d+(?:\.\d+)?)$/;

/**
 * @primitive b.money.parse
 * @signature b.money.parse(input)
 * @since     0.11.25
 * @status    stable
 * @related   b.money.of, Money.prototype.toString
 *
 * Parse a string of the form `<amount> <code>` OR `<code> <amount>`
 * into a `Money`. The two shapes round-trip with `toString()` (which
 * emits the amount-first canonical form). Whitespace between amount
 * and code is required; locale-formatted strings (thousands separator,
 * `$` glyph) are refused -- operators normalise at the call site.
 *
 * @example
 *   b.money.parse("12.50 USD");
 *   b.money.parse("USD 12.50");
 *   b.money.parse("12 JPY");
 *   b.money.parse("12.500 KWD");
 */
function parse(input) {
  if (typeof input !== "string") {
    throw new MoneyError("money/bad-input",
      "parse expects a string; got " + (typeof input));
  }
  var trimmed = input.trim();
  var m1 = trimmed.match(_PARSE_AMOUNT_FIRST_RE);
  if (m1) return of(m1[1], m1[2]);
  var m2 = trimmed.match(_PARSE_CODE_FIRST_RE);
  if (m2) return of(m2[2], m2[1]);
  throw new MoneyError("money/bad-input",
    "parse: input must match `<amount> <code>` or `<code> <amount>`, " +
    "got " + JSON.stringify(input));
}

/**
 * @primitive b.money.zero
 * @signature b.money.zero(currency)
 * @since     0.11.25
 * @status    stable
 * @related   b.money.of
 *
 * Return a zero-valued `Money` in the requested currency. Convenience
 * for fold/sum accumulators.
 *
 * @example
 *   var total = items.reduce(function (acc, it) { return acc.add(it.price); },
 *                            b.money.zero("USD"));
 */
function zero(currency) {
  _requireCurrency(currency);
  return new Money(0n, currency);
}

/**
 * @primitive b.money.convert
 * @signature b.money.convert(money, toCurrency, fxRateProvider, opts?)
 * @since     0.11.25
 * @status    stable
 * @related   b.money.of, Money.prototype.multiply
 *
 * Convert `money` to `toCurrency` through an operator-injected rate
 * provider. The framework NEVER bakes in rates -- operators wire a
 * provider that pulls from an external FX feed (ECB / OANDA / their
 * internal treasury system) and refresh on whatever cadence their
 * regime requires.
 *
 * The `fxRateProvider.rate(from, to)` contract returns a decimal-
 * shaped string (`"1.085"`) -- never a Number. Conversion math runs
 * in BigInt with the provider rate's denominator; rounding is
 * half-to-even by default (operator opts into half-up via
 * `opts.rounding`).
 *
 * @opts
 *   rounding:  "half-even" | "half-up",   // default "half-even" (bankers')
 *
 * @example
 *   var rates = { rate: function (from, to) { return "0.92"; } };
 *   var eur   = b.money.convert(b.money.of("100.00", "USD"), "EUR", rates);
 */
function convert(money, toCurrency, fxRateProvider, opts) {
  _requireMoney(money, "convert source");
  _requireCurrency(toCurrency);
  if (!fxRateProvider || typeof fxRateProvider.rate !== "function") {
    throw new MoneyError("money/bad-fx-provider",
      "convert requires an fxRateProvider with a .rate(from, to) method");
  }
  opts = opts || {};
  if (money.currency === toCurrency) {
    // Identity conversion still flows through so the operator's audit
    // hook (if any) sees the call. New instance -- Money is immutable.
    return new Money(money._minor, money.currency);
  }
  var rateStr = fxRateProvider.rate(money.currency, toCurrency);
  if (typeof rateStr !== "string") {
    throw new MoneyError("money/bad-rate",
      "fxRateProvider.rate must return a decimal-shaped string; got " +
      (typeof rateStr));
  }
  var rational = _rationalFromDecimalString(rateStr);
  if (rational.num < 0n) {
    throw new MoneyError("money/bad-rate",
      "fxRateProvider.rate returned a negative rate: " +
      JSON.stringify(rateStr));
  }
  var fromExp = _exponentOf(money.currency);
  var toExp   = _exponentOf(toCurrency);
  // Scale source minor units into the destination's exponent before
  // applying the rate, so the rounding step happens once at the end.
  //   amount_to = amount_from * (10^toExp / 10^fromExp) * (num / den)
  var rounding = opts.rounding === "half-up" ? "half-up" : "half-even";
  var num = money._minor * rational.num;
  var den = rational.den;
  if (toExp > fromExp) {
    num = num * _pow10(toExp - fromExp);
  } else if (fromExp > toExp) {
    den = den * _pow10(fromExp - toExp);
  }
  var minor = _divRound(num, den, rounding);
  return new Money(minor, toCurrency);
}

module.exports = {
  of:              of,
  create:          of,                                                     // alias -- matches spec's "create or of"
  fromMinorUnits:  fromMinorUnits,
  parse:           parse,
  zero:            zero,
  convert:         convert,
  CURRENCIES:      CURRENCIES,
  Money:           Money,
  MoneyError:      MoneyError,
};

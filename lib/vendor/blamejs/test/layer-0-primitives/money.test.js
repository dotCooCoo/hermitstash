"use strict";

var helpers = require("../helpers");
var check = helpers.check;
var b = require("../../");

function _threw(fn) {
  try { fn(); return null; }
  catch (e) { return e; }
}

function run() {
  // ---- Public surface ----
  check("b.money exposed",                  typeof b.money === "object");
  check("b.money.of function",              typeof b.money.of === "function");
  check("b.money.create alias",             typeof b.money.create === "function");
  check("b.money.fromMinorUnits function",  typeof b.money.fromMinorUnits === "function");
  check("b.money.parse function",           typeof b.money.parse === "function");
  check("b.money.zero function",            typeof b.money.zero === "function");
  check("b.money.convert function",         typeof b.money.convert === "function");
  check("b.money.CURRENCIES exposed",       typeof b.money.CURRENCIES === "object");
  check("b.money.MoneyError exposed",       typeof b.money.MoneyError === "function");
  check("b.money.roundMinor function",      typeof b.money.roundMinor === "function");
  check("b.money.Money class exposed",      typeof b.money.Money === "function");

  // ---- roundMinor: cash-rounding to an increment (BigInt minor units) ----
  check("roundMinor: CHF 12.32 → nearest 0.05 (half-even)", b.money.roundMinor(1232n, 5n) === 1230n);
  check("roundMinor: tie → half-even picks even multiple",  b.money.roundMinor(25n, 10n, "half-even") === 20n);
  check("roundMinor: tie → half-up away from zero",         b.money.roundMinor(25n, 10n, "half-up") === 30n);
  check("roundMinor: negative tie → half-up away from zero", b.money.roundMinor(-25n, 10n, "half-up") === -30n);
  check("roundMinor: floor toward -inf",                    b.money.roundMinor(27n, 10n, "floor") === 20n);
  check("roundMinor: ceiling toward +inf",                  b.money.roundMinor(21n, 10n, "ceiling") === 30n);
  check("roundMinor: exact multiple returns unchanged",     b.money.roundMinor(30n, 10n) === 30n);
  check("roundMinor: safe-integer Number coerced to BigInt", b.money.roundMinor(25, 10n, "half-up") === 30n);
  check("roundMinor: bad mode throws money/bad-rounding-mode",
        (function () { try { b.money.roundMinor(10n, 5n, "nope"); return null; } catch (e) { return e.code; } })()
          === "money/bad-rounding-mode");
  check("roundMinor: non-integer minor throws money/bad-minor-units",
        (function () { try { b.money.roundMinor(1.5, 5n); return null; } catch (e) { return e.code; } })()
          === "money/bad-minor-units");
  check("b.money.Money is the prototype",   b.money.of("1.00", "USD") instanceof b.money.Money);
  check("CURRENCIES is frozen",             Object.isFrozen(b.money.CURRENCIES));
  check("CURRENCIES.USD exponent",          b.money.CURRENCIES.USD === 2);
  check("CURRENCIES.JPY exponent",          b.money.CURRENCIES.JPY === 0);
  check("CURRENCIES.KWD exponent",          b.money.CURRENCIES.KWD === 3);
  check("CURRENCIES.CLF exponent",          b.money.CURRENCIES.CLF === 4);
  check("CURRENCIES.EUR exponent",          b.money.CURRENCIES.EUR === 2);
  check("CURRENCIES.KRW exponent",          b.money.CURRENCIES.KRW === 0);

  // ---- Construction: BigInt ----
  var a = b.money.of(1250n, "USD");
  check("of(1250n, USD): minor units", a.toMinorUnits() === 1250n);
  check("of(1250n, USD): currency",    a.currency === "USD");
  check("of(1250n, USD): toString",    a.toString() === "12.50 USD");

  // ---- Construction: string ----
  var s = b.money.of("12.50", "USD");
  check("of('12.50', USD): minor",   s.toMinorUnits() === 1250n);
  check("of('12.50', USD): toString", s.toString() === "12.50 USD");

  // ---- Construction: alias ----
  var aliased = b.money.create("3.14", "USD");
  check("create alias works", aliased.toMinorUnits() === 314n);

  // ---- Construction: Number REFUSED ----
  var rejNum = _threw(function () { b.money.of(12.5, "USD"); });
  check("of(Number, USD) refused",  !!rejNum && rejNum.isMoneyError);
  check("of(Number) error code",    rejNum && rejNum.code === "money/number-refused");

  // ---- Bad currency throws ----
  var badCcy = _threw(function () { b.money.of(100n, "XYZ"); });
  check("unknown currency refused", !!badCcy && badCcy.isMoneyError &&
        badCcy.code === "money/bad-currency");

  // ---- Bad amount shapes ----
  var sciNot = _threw(function () { b.money.of("1e3", "USD"); });
  check("scientific-notation refused", !!sciNot && sciNot.isMoneyError);

  var thouSep = _threw(function () { b.money.of("1,000.00", "USD"); });
  check("thousands-separator refused", !!thouSep && thouSep.isMoneyError);

  var emptyAmt = _threw(function () { b.money.of("", "USD"); });
  check("empty amount refused", !!emptyAmt && emptyAmt.isMoneyError);

  // Fractional-precision overflow: USD has exp=2, can't accept 3 fracs.
  var precLoss = _threw(function () { b.money.of("12.500", "USD"); });
  check("precision-loss refused", !!precLoss &&
        precLoss.code === "money/precision-loss");

  // ---- The classic float-fail ----
  var dimes = b.money.of("0.10", "USD");
  var twentyc = b.money.of("0.20", "USD");
  var sum = dimes.add(twentyc);
  check("0.10 + 0.20 = 0.30 exactly", sum.toMinorUnits() === 30n);
  check("0.30 toString",              sum.toString() === "0.30 USD");

  // ---- Cross-currency arithmetic throws ----
  var usd = b.money.of("10.00", "USD");
  var eur = b.money.of("10.00", "EUR");
  var addCross = _threw(function () { usd.add(eur); });
  check("USD + EUR refused on add", !!addCross && addCross.isMoneyError &&
        addCross.code === "money/currency-mismatch");
  var subCross = _threw(function () { usd.subtract(eur); });
  check("USD - EUR refused on sub", !!subCross && subCross.isMoneyError);
  var ltCross = _threw(function () { usd.lessThan(eur); });
  check("USD < EUR refused on cmp", !!ltCross && ltCross.isMoneyError);

  // ---- Subtract ----
  var diff = b.money.of("3.00", "USD").subtract(b.money.of("1.25", "USD"));
  check("3.00 - 1.25 = 1.75", diff.toString() === "1.75 USD");

  // ---- Multiply ----
  var tripled = b.money.of("3.33", "USD").multiply(3n);
  check("3.33 * 3 = 9.99", tripled.toString() === "9.99 USD");

  var taxed = b.money.of("100.00", "USD").multiply("1.085");
  check("100.00 * 1.085 = 108.50", taxed.toString() === "108.50 USD");

  var ratPair = b.money.of("100.00", "USD").multiply([6n, 5n]);
  check("100.00 * (6/5) = 120.00", ratPair.toString() === "120.00 USD");

  var mulNumRej = _threw(function () {
    b.money.of("1.00", "USD").multiply(1.5);
  });
  check("multiply(Number) refused", !!mulNumRej && mulNumRej.isMoneyError);

  // ---- Allocate: $10 / 3 ----
  var ten = b.money.of("10.00", "USD");
  var parts = ten.allocate([1, 1, 1]);
  check("allocate(10.00, [1,1,1]): length", parts.length === 3);
  check("allocate(10.00, [1,1,1]): [0]", parts[0].toString() === "3.34 USD");
  check("allocate(10.00, [1,1,1]): [1]", parts[1].toString() === "3.33 USD");
  check("allocate(10.00, [1,1,1]): [2]", parts[2].toString() === "3.33 USD");
  var allocSum = parts[0].add(parts[1]).add(parts[2]);
  check("allocate sum preserves total", allocSum.equals(ten));

  // ---- Allocate with weighted shares ----
  var hundred = b.money.of("100.00", "USD");
  var weighted = hundred.allocate([60, 40]);
  check("allocate(100, [60,40]): [0]", weighted[0].toString() === "60.00 USD");
  check("allocate(100, [60,40]): [1]", weighted[1].toString() === "40.00 USD");
  var weightedSum = weighted[0].add(weighted[1]);
  check("weighted sum preserves total", weightedSum.equals(hundred));

  // ---- Allocate BigInt weights ----
  var bigWeights = ten.allocate([2n, 1n]);
  check("allocate BigInt weights [0]", bigWeights[0].toString() === "6.67 USD");
  check("allocate BigInt weights [1]", bigWeights[1].toString() === "3.33 USD");

  // ---- Allocate edge cases ----
  var negAllocW = _threw(function () { ten.allocate([1, -1]); });
  check("negative weight refused", !!negAllocW && negAllocW.isMoneyError);
  var zeroWSum = _threw(function () { ten.allocate([0, 0]); });
  check("zero-sum weights refused", !!zeroWSum && zeroWSum.isMoneyError);
  var emptyW = _threw(function () { ten.allocate([]); });
  check("empty weights refused", !!emptyW && emptyW.isMoneyError);
  var nonIntW = _threw(function () { ten.allocate([1.5, 1]); });
  check("non-integer weight refused", !!nonIntW && nonIntW.isMoneyError);

  // ---- Negate / abs ----
  var pos = b.money.of("5.00", "USD");
  var neg = pos.negate();
  check("negate: minor", neg.toMinorUnits() === -500n);
  check("negate: toString", neg.toString() === "-5.00 USD");
  check("abs of negative", neg.abs().equals(pos));
  check("abs of positive", pos.abs().equals(pos));
  check("negate twice equals", pos.negate().negate().equals(pos));

  // ---- Comparison ----
  var five  = b.money.of("5.00", "USD");
  var six   = b.money.of("6.00", "USD");
  var five2 = b.money.of("5.00", "USD");
  check("5 == 5", five.equals(five2));
  check("5 != 6", !five.equals(six));
  check("5 < 6",   five.lessThan(six));
  check("6 > 5",   six.greaterThan(five));
  check("5 <= 5",  five.lessThanOrEqual(five2));
  check("5 <= 6",  five.lessThanOrEqual(six));
  check("5 >= 5",  five.greaterThanOrEqual(five2));
  check("6 >= 5",  six.greaterThanOrEqual(five));
  check("!(5 > 6)", !five.greaterThan(six));
  check("isZero on 0", b.money.zero("USD").isZero());
  check("isZero on 5", !five.isZero());
  check("isNegative on -5", neg.isNegative());
  check("isPositive on 5",  five.isPositive());

  // equals across currencies: false (no throw -- equality is well-defined)
  check("USD 5 != EUR 5", !b.money.of("5.00", "USD").equals(b.money.of("5.00", "EUR")));

  // ---- JPY (0-exponent) round-trip ----
  var yen = b.money.of("1234", "JPY");
  check("JPY 1234 minor",     yen.toMinorUnits() === 1234n);
  check("JPY 1234 toString",  yen.toString() === "1234 JPY");
  var yenAdd = yen.add(b.money.of("1", "JPY"));
  check("JPY arithmetic",     yenAdd.toString() === "1235 JPY");
  var jpyFrac = _threw(function () { b.money.of("12.5", "JPY"); });
  check("JPY refuses fractional", !!jpyFrac && jpyFrac.isMoneyError);

  // ---- KWD (3-exponent) round-trip ----
  var dinar = b.money.of("12.500", "KWD");
  check("KWD 12.500 minor",    dinar.toMinorUnits() === 12500n);
  check("KWD 12.500 toString", dinar.toString() === "12.500 KWD");
  var dinarSmall = b.money.of("0.001", "KWD");
  check("KWD 0.001 minor", dinarSmall.toMinorUnits() === 1n);

  // ---- CLF (4-exponent) ----
  var uf = b.money.of("1.2345", "CLF");
  check("CLF 1.2345 minor",    uf.toMinorUnits() === 12345n);
  check("CLF 1.2345 toString", uf.toString() === "1.2345 CLF");

  // ---- parse() shapes ----
  check("parse '12.50 USD'",   b.money.parse("12.50 USD").toMinorUnits() === 1250n);
  check("parse 'USD 12.50'",   b.money.parse("USD 12.50").toMinorUnits() === 1250n);
  check("parse '12 JPY'",      b.money.parse("12 JPY").toMinorUnits() === 12n);
  check("parse 'JPY 12'",      b.money.parse("JPY 12").toMinorUnits() === 12n);
  check("parse '12.500 KWD'",  b.money.parse("12.500 KWD").toMinorUnits() === 12500n);
  check("parse '-3.14 EUR'",   b.money.parse("-3.14 EUR").toMinorUnits() === -314n);
  check("parse trims whitespace", b.money.parse("  12.50 USD  ").toMinorUnits() === 1250n);

  var badParse1 = _threw(function () { b.money.parse("12.50USD"); });
  check("parse rejects no-space", !!badParse1 && badParse1.isMoneyError);
  var badParse2 = _threw(function () { b.money.parse("$12.50"); });
  check("parse rejects glyph", !!badParse2 && badParse2.isMoneyError);
  var badParse3 = _threw(function () { b.money.parse(""); });
  check("parse rejects empty", !!badParse3 && badParse3.isMoneyError);
  var badParse4 = _threw(function () { b.money.parse(12.5); });
  check("parse rejects Number input", !!badParse4 && badParse4.isMoneyError);

  // ---- toString round-trip via parse ----
  var rt = b.money.of("123.45", "USD");
  check("toString -> parse round-trip", b.money.parse(rt.toString()).equals(rt));
  var rtJpy = b.money.of("99", "JPY");
  check("JPY toString -> parse round-trip", b.money.parse(rtJpy.toString()).equals(rtJpy));
  var rtKwd = b.money.of("0.001", "KWD");
  check("KWD toString -> parse round-trip", b.money.parse(rtKwd.toString()).equals(rtKwd));

  // ---- toJSON / fromJSON round-trip ----
  var price = b.money.of("42.99", "EUR");
  var j = price.toJSON();
  check("toJSON minorUnits string",  j.minorUnits === "4299");
  check("toJSON currency",           j.currency === "EUR");
  // round-trip via fromMinorUnits
  var restored = b.money.fromMinorUnits(BigInt(j.minorUnits), j.currency);
  check("fromMinorUnits round-trip", restored.equals(price));

  // JSON.stringify path
  var jsonStr = JSON.stringify(price);
  var parsedJson = JSON.parse(jsonStr);
  var restored2 = b.money.fromMinorUnits(BigInt(parsedJson.minorUnits), parsedJson.currency);
  check("JSON.stringify round-trip", restored2.equals(price));

  // ---- zero ----
  var z = b.money.zero("USD");
  check("zero is zero", z.isZero());
  check("zero currency", z.currency === "USD");
  check("zero toString", z.toString() === "0.00 USD");

  // ---- format ----
  var f = b.money.of("1234.56", "USD");
  var formatted = f.format("en-US");
  check("format produces string", typeof formatted === "string" && formatted.length > 0);
  // The exact glyph varies by ICU version; just confirm "1,234" appears
  // somewhere in en-US output and "USD" or "$" is in there.
  check("format en-US contains decimal + grouping",
        /1[\s,]?234/.test(formatted) && /(\$|USD)/.test(formatted));
  // No-locale call doesn't throw.
  check("format() no-locale no-throw", typeof f.format() === "string");

  // ---- convert ----
  var rates = {
    rate: function (from, to) {
      if (from === "USD" && to === "EUR") return "0.92";
      if (from === "USD" && to === "JPY") return "150.25";
      if (from === "JPY" && to === "USD") return "0.00665";
      if (from === "USD" && to === "KWD") return "0.31";
      return "1.00";
    },
  };
  var usdToEur = b.money.convert(b.money.of("100.00", "USD"), "EUR", rates);
  check("convert USD->EUR",       usdToEur.toString() === "92.00 EUR");
  check("convert preserves currency tag", usdToEur.currency === "EUR");

  // USD -> JPY (exp 2 -> 0)
  var usdToJpy = b.money.convert(b.money.of("10.00", "USD"), "JPY", rates);
  // 10.00 * 150.25 = 1502.50 USD * 150.25 = 1000 minor * 150.25 / 100 (rate denom) * 1/100 (exp diff) = ?
  // 1000 (cents) * 15025 (rate num) / 100 (rate den) = 150250.  Then scale 1/100 (USD exp 2 to JPY exp 0): 150250 / 100 = 1502.5 -> half-even -> 1502
  check("convert USD->JPY exp drop", usdToJpy.toMinorUnits() === 1502n);

  // USD -> KWD (exp 2 -> 3) -- scale UP
  var usdToKwd = b.money.convert(b.money.of("1.00", "USD"), "KWD", rates);
  // 100 (cents) * 31 (rate num) / 100 (rate den) = 31, then * 10 (exp diff) = 310 fils = 0.310 KWD
  check("convert USD->KWD exp grow", usdToKwd.toString() === "0.310 KWD");

  // Identity conversion ok
  var ident = b.money.convert(b.money.of("5.00", "USD"), "USD", rates);
  check("convert identity",       ident.toString() === "5.00 USD");

  // Bad rate provider
  var noProv = _threw(function () { b.money.convert(b.money.of("1.00", "USD"), "EUR", null); });
  check("convert refuses missing provider", !!noProv && noProv.isMoneyError);
  var badProv = _threw(function () { b.money.convert(b.money.of("1.00", "USD"), "EUR", {}); });
  check("convert refuses no-rate-fn provider", !!badProv && badProv.isMoneyError);
  var numRate = _threw(function () {
    b.money.convert(b.money.of("1.00", "USD"), "EUR", { rate: function () { return 0.92; } });
  });
  check("convert refuses Number rate", !!numRate && numRate.isMoneyError);
  var negRate = _threw(function () {
    b.money.convert(b.money.of("1.00", "USD"), "EUR", { rate: function () { return "-0.5"; } });
  });
  check("convert refuses negative rate", !!negRate && negRate.isMoneyError);

  // ---- Banker's rounding (half-to-even) ----
  // Construct a conversion where the result is exactly half a minor unit.
  // 1 USD cent * rate "0.005" -> 0.005 USD-equiv, denominator 1000, source 1
  // num = 1 * 5 = 5; den = 1000; result = 5/1000 = 0.005.
  // We want a setup where 2*r == d to hit the half-even branch.
  // Easier: convert 5n minor of USD with rate "0.001" -> 5/1000 = 0.005,
  // target USD exp 2; same exponent (USD -> USD identity blocks).
  // Use USD -> EUR with rate that produces exactly half.
  //
  // 50 cents * rate "0.005" = 0.25 (half a cent at EUR exp 2).
  // num = 50 * 5 = 250; den = 1000; 2*250 = 500 == 1000? No, 500 != 1000.
  // result = 250 / 1000 = 0.25 -> not at boundary.
  //
  // Try: 5 cents * rate "0.10" -> 0.5 cents at EUR exp 2.
  // num = 5 * 10 = 50; den = 100; 2*0 = 0 ? No: q=0, r=50; 2*50=100==den; half. half-even: q=0 even -> 0.
  var halfDown = b.money.convert(
    b.money.of(5n, "USD"),
    "EUR",
    { rate: function () { return "0.10"; } }
  );
  check("half-even rounds 0.5 -> 0 (even)", halfDown.toMinorUnits() === 0n);

  // 15 cents * 0.10 -> 1.5 cents EUR. half-even: q=1 odd -> 2.
  var halfUp1 = b.money.convert(
    b.money.of(15n, "USD"),
    "EUR",
    { rate: function () { return "0.10"; } }
  );
  check("half-even rounds 1.5 -> 2 (odd up)", halfUp1.toMinorUnits() === 2n);

  // 25 cents * 0.10 -> 2.5 cents EUR. half-even: q=2 even -> 2.
  var halfDown2 = b.money.convert(
    b.money.of(25n, "USD"),
    "EUR",
    { rate: function () { return "0.10"; } }
  );
  check("half-even rounds 2.5 -> 2 (even)", halfDown2.toMinorUnits() === 2n);

  // half-up opt: 5 cents -> 1 (not 0)
  var halfUpOpt = b.money.convert(
    b.money.of(5n, "USD"),
    "EUR",
    { rate: function () { return "0.10"; } },
    { rounding: "half-up" }
  );
  check("half-up rounds 0.5 -> 1", halfUpOpt.toMinorUnits() === 1n);

  // ---- Immutability ----
  var imm = b.money.of("5.00", "USD");
  check("Money is frozen", Object.isFrozen(imm));
  // Mutation attempts silently no-op under strict mode? Actually -- frozen
  // throws under strict. Test that the visible state is unchanged after a
  // try-write.
  try { imm._minor = 999n; } catch (_e) { /* expected under strict */ }
  check("Money minor unchanged after write attempt", imm.toMinorUnits() === 500n);

  // ---- Reduce / fold ergonomics (the use case the spec calls out) ----
  var items = [
    b.money.of("1.99", "USD"),
    b.money.of("2.50", "USD"),
    b.money.of("0.01", "USD"),
  ];
  var total = items.reduce(function (acc, it) { return acc.add(it); },
                           b.money.zero("USD"));
  check("reduce sum: 1.99 + 2.50 + 0.01", total.toString() === "4.50 USD");

  // ---- Negative-amount round-trip ----
  var negParsed = b.money.parse("-12.50 USD");
  check("parse negative",      negParsed.toMinorUnits() === -1250n);
  check("negative toString",   negParsed.toString() === "-12.50 USD");
  check("negative add",        negParsed.add(b.money.of("15.00", "USD")).toString() === "2.50 USD");
  check("negative abs",        negParsed.abs().toString() === "12.50 USD");
}

module.exports = { run: run };

if (require.main === module) {
  Promise.resolve(run()).then(
    function () { console.log("OK -- " + helpers.getChecks() + " checks passed"); },
    function (e) { console.error("FAIL:", e.stack || e); process.exit(1); }
  );
}

"use strict";
/**
 * b.safeJson.stringifyForScript — JSON safe to embed verbatim inside an
 * inline <script>. Raw JSON.stringify leaves <, >, & literal, so a value
 * containing "</script>" closes the surrounding element (XSS); the
 * U+2028 / U+2029 separators are also illegal unescaped in a script on
 * older parsers. This escapes all of them to \uXXXX — the parsed value is
 * byte-identical.
 */

var helpers = require("../helpers");
var b       = helpers.b;
var check   = helpers.check;

function run() {
  // </script> in a value is neutralised but round-trips.
  var payload = { url: "/a</script><script>alert(1)</script>", amp: "a&b", lt: "x<y>z" };
  var out = b.safeJson.stringifyForScript(payload);
  check("no raw </script> survives", out.indexOf("</script>") === -1);
  check("< is escaped to \\u003c", out.indexOf("\\u003c") !== -1 && out.indexOf("<") === -1);
  check("> is escaped to \\u003e", out.indexOf(">") === -1);
  check("& is escaped to \\u0026", out.indexOf("&") === -1);
  check("round-trips to the identical value", JSON.parse(out).url === payload.url &&
        JSON.parse(out).amp === "a&b" && JSON.parse(out).lt === "x<y>z");

  // U+2028 / U+2029 (built via code point so this source stays ASCII).
  var sep = { s: "a" + String.fromCharCode(0x2028) + "b" + String.fromCharCode(0x2029) + "c" };
  var outSep = b.safeJson.stringifyForScript(sep);
  check("U+2028 escaped to \\u2028", outSep.indexOf("\\u2028") !== -1 &&
        outSep.indexOf(String.fromCharCode(0x2028)) === -1);
  check("U+2029 escaped to \\u2029", outSep.indexOf("\\u2029") !== -1 &&
        outSep.indexOf(String.fromCharCode(0x2029)) === -1);
  check("separators round-trip to the identical value",
        JSON.parse(outSep).s === sep.s);

  console.log("OK — safeJson.stringifyForScript (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };

if (require.main === module) {
  try { run(); } catch (e) { console.error(e); process.exit(1); }
}

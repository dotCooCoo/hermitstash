"use strict";
// b.template.escapeHtml — the {{ expr }} interpolation escaper (XSS boundary).
// Now delegates to the centralized markup-escape so the five-character HTML set
// is defined in ONE place; a divergence between this and the shared escaper is
// an XSS / XML-injection surface. This pins the contract (all five chars, &
// first so emitted entities aren't double-escaped, null/undefined → "",
// non-string coercion) so the delegation can't silently regress.

var helpers = require("../helpers");
var b     = helpers.b;
var check = helpers.check;

function run() {
  var esc = b.template.escapeHtml;

  check("escapes <", esc("<script>") === "&lt;script&gt;");
  check("escapes & first (no double-escape of emitted entities)", esc("a&b") === "a&amp;b");
  check("escapes double-quote", esc('say "hi"') === "say &quot;hi&quot;");
  check("escapes apostrophe to numeric form (single-quoted attr safety)",
        esc("it's") === "it&#x27;s");
  check("all five together", esc("<a href='x' title=\"y\">&</a>") ===
        "&lt;a href=&#x27;x&#x27; title=&quot;y&quot;&gt;&amp;&lt;/a&gt;");

  // & is escaped first so a literal "&lt;" in the input becomes "&amp;lt;",
  // not "&lt;" (which would let an attacker inject a pre-formed entity).
  check("pre-formed entity in input is neutralized (& escaped first)",
        esc("&lt;") === "&amp;lt;");

  check("null → empty string", esc(null) === "");
  check("undefined → empty string", esc(undefined) === "");
  check("number coerced + returned", esc(42) === "42");
  check("boolean coerced", esc(true) === "true");
  check("plain string unchanged", esc("hello world") === "hello world");
  check("empty string → empty string", esc("") === "");

  console.log("OK — template.escapeHtml (" + helpers.getChecks() + " checks)");
}

module.exports = { run: run };
if (require.main === module) {
  try { run(); process.exit(0); }
  catch (e) { console.error("FAIL: " + (e && e.message)); process.exit(1); }
}

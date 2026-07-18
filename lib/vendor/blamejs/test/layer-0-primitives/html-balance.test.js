// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";

var helpers = require("../helpers");
var b      = helpers.b;
var check  = helpers.check;

function run() {
  // Balanced cases.
  check("balanced empty",                b.htmlBalance.check("")                          === null);
  check("balanced text only",            b.htmlBalance.check("Hello world")               === null);
  check("balanced single tag",           b.htmlBalance.check("<p>Hi</p>")                  === null);
  check("balanced nested",               b.htmlBalance.check("<div><p>x</p></div>")        === null);
  check("balanced void tag",             b.htmlBalance.check("<p>x<br>y</p>")              === null);
  check("balanced self-closing",         b.htmlBalance.check("<p>x<img src=y/></p>")       === null);
  check("balanced comment",              b.htmlBalance.check("<p><!-- ok --></p>")         === null);
  check("balanced quoted attr with >",   b.htmlBalance.check('<a href="/x?a=1>2">y</a>')   === null);
  check("balanced raw-text script",      b.htmlBalance.check("<script>if (a<b) f();</script>") === null);

  // Unbalanced cases — must return a problem object.
  var p1 = b.htmlBalance.check("<div>broken");
  check("unclosed div detected",         !!p1 && p1.code === "html/unclosed-tag");
  var p2 = b.htmlBalance.check("</p>");
  check("orphan close detected",         !!p2 && p2.code === "html/orphan-close");
  var p3 = b.htmlBalance.check("<div><p></div></p>");
  check("mismatched close detected",     !!p3 && p3.code === "html/mismatched-close");
  var p4 = b.htmlBalance.check("<!-- never closes");
  check("unterminated comment detected", !!p4 && p4.code === "html/unterminated-comment");
  var p5 = b.htmlBalance.check("<p>x</br></p>");
  check("close on void element rejected", !!p5 && p5.code === "html/void-close");

  // ---- checkSafe — structural balance composed with guard-html security ----

  // Balanced + content-safe: no structural issue, no guard issues, ok:true.
  var safe = b.htmlBalance.checkSafe("<p>hello</p>", { profile: "strict" });
  check("checkSafe: clean html balanceIssue null", safe.balanceIssue === null);
  check("checkSafe: clean html no guard issues",   safe.guardIssues.length === 0);
  check("checkSafe: clean html ok true",           safe.ok === true);

  // Balanced but content-UNSAFE: an inline event-handler attribute is
  // structurally fine (balanceIssue null) but the strict guard profile
  // refuses it — ok flips false with the guard issue surfaced.
  var evt = b.htmlBalance.checkSafe("<div onclick=\"x()\">hi</div>", { profile: "strict" });
  check("checkSafe: event-handler balanceIssue null", evt.balanceIssue === null);
  check("checkSafe: event-handler guard issue raised", evt.guardIssues.length >= 1);
  check("checkSafe: event-handler kind is event-handler",
        evt.guardIssues[0].kind === "event-handler");
  check("checkSafe: event-handler ok false", evt.ok === false);

  // Structurally BROKEN with no profile: only the cheap balance() runs,
  // guard checks are skipped (no profile / contentSafety), ok:false on the
  // structural problem alone.
  var broken = b.htmlBalance.checkSafe("<div>broken");
  check("checkSafe: no-profile surfaces balance issue",
        !!broken.balanceIssue && broken.balanceIssue.code === "html/unclosed-tag");
  check("checkSafe: no-profile skips guard scan", broken.guardIssues.length === 0);
  check("checkSafe: no-profile ok false", broken.ok === false);

  // contentSafety:{ profile } is the shared shape with b.fileUpload /
  // b.staticServe and must behave identically to a bare profile opt.
  var viaCs = b.htmlBalance.checkSafe("<div onclick=\"x()\">hi</div>",
    { contentSafety: { profile: "strict" } });
  check("checkSafe: contentSafety shape matches profile opt",
        viaCs.ok === false && viaCs.guardIssues.length >= 1);

  // Balanced + safe with no opts at all → guard scan skipped, ok:true.
  var noOpts = b.htmlBalance.checkSafe("<section><p>fine</p></section>");
  check("checkSafe: no-opts balanced content ok true", noOpts.ok === true);
}

module.exports = { run: run };

if (require.main === module) {
  run();
  console.log("OK — " + helpers.getChecks() + " checks passed");
}

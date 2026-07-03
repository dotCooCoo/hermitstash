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
}

module.exports = { run: run };

if (require.main === module) {
  run();
  console.log("OK — " + helpers.getChecks() + " checks passed");
}
